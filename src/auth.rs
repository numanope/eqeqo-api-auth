use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenRecord {
  pub token: String,
  pub payload: Value,
  pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
  pub ttl_seconds: i64,
  pub renew_threshold_seconds: i64,
  pub service_ttl_seconds: i64,
}

impl TokenConfig {
  const DEFAULT_USER_TTL_SECONDS: i64 = 300;
  const DEFAULT_SERVICE_TTL_SECONDS: i64 = 60 * 60 * 24 * 7;
  const DEFAULT_RENEW_THRESHOLD_SECONDS: i64 = 30;

  fn load_env_seconds(key: &str, fallback: i64) -> i64 {
    env::var(key)
      .ok()
      .and_then(|v| v.parse::<i64>().ok())
      .unwrap_or(fallback)
  }

  pub fn load() -> Self {
    let ttl_seconds =
      Self::load_env_seconds("USER_TOKEN_TTL_SECONDS", Self::DEFAULT_USER_TTL_SECONDS);
    let renew_threshold_seconds = Self::load_env_seconds(
      "TOKEN_RENEW_THRESHOLD_SECONDS",
      Self::DEFAULT_RENEW_THRESHOLD_SECONDS,
    );
    let service_ttl_seconds = Self::load_env_seconds(
      "SERVICE_TOKEN_TTL_SECONDS",
      Self::DEFAULT_SERVICE_TTL_SECONDS,
    );
    Self {
      ttl_seconds,
      renew_threshold_seconds,
      service_ttl_seconds,
    }
  }
}

#[derive(Debug, Clone)]
pub struct TokenManager<'a> {
  pool: &'a Pool<Postgres>,
  config: TokenConfig,
}

#[derive(Debug)]
pub enum TokenError {
  NotFound,
  Expired,
  Database(sqlx::Error),
}

impl From<sqlx::Error> for TokenError {
  fn from(err: sqlx::Error) -> Self {
    TokenError::Database(err)
  }
}

#[derive(Debug, Serialize)]
pub struct TokenIssue {
  pub token: String,
  pub expires_at: i64,
}

#[derive(Debug)]
pub struct TokenValidation {
  pub record: TokenRecord,
  pub renewed: bool,
  pub expires_at: i64,
}

impl<'a> TokenManager<'a> {
  pub fn new(pool: &'a Pool<Postgres>) -> Self {
    let config = TokenConfig::load();
    Self { pool, config }
  }

  pub fn ttl(&self) -> i64 {
    self.config.ttl_seconds
  }

  pub fn service_ttl(&self) -> i64 {
    self.config.service_ttl_seconds
  }

  fn now_epoch() -> i64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs() as i64
  }

  fn generate_token_value(secret: &str, now: i64) -> String {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(&random);
    hasher.update(now.to_be_bytes());

    let digest = hasher.finalize();
    format!("{:x}", digest)
  }

  async fn insert_token(
    &self,
    token: &str,
    payload: &Value,
    expires_at: i64,
  ) -> Result<(), sqlx::Error> {
    sqlx::query(
      "INSERT INTO auth.tokens_cache (token, payload, expires_at)
        VALUES ($1, $2, $3)",
    )
    .bind(token)
    .bind(payload)
    .bind(expires_at)
    .execute(self.pool)
    .await?;
    Ok(())
  }

  async fn fetch_token(&self, token: &str) -> Result<Option<TokenRecord>, sqlx::Error> {
    sqlx::query_as::<_, TokenRecord>(
      "SELECT token, payload, expires_at FROM auth.tokens_cache WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(self.pool)
    .await
  }

  async fn touch_token(
    &self,
    token: &str,
    previous_expires_at: i64,
    new_expires_at: i64,
  ) -> Result<Option<TokenRecord>, sqlx::Error> {
    let updated = sqlx::query_as::<_, TokenRecord>(
      "UPDATE auth.tokens_cache
        SET expires_at = $1
        WHERE token = $2 AND expires_at = $3
        RETURNING token, payload, expires_at",
    )
    .bind(new_expires_at)
    .bind(token)
    .bind(previous_expires_at)
    .fetch_optional(self.pool)
    .await?;
    Ok(updated)
  }

  fn compute_expires_at(&self, modified_at: i64) -> i64 {
    modified_at + self.config.ttl_seconds
  }

  fn compute_service_expires_at(&self, modified_at: i64) -> i64 {
    modified_at + self.config.service_ttl_seconds
  }

  pub async fn issue_token(&self, payload: Value) -> Result<TokenIssue, sqlx::Error> {
    let now = Self::now_epoch();
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "local_secret".to_string());
    let token = Self::generate_token_value(&secret, now);
    let expires_at = self.compute_expires_at(now);
    self.insert_token(&token, &payload, expires_at).await?;
    Ok(TokenIssue {
      token,
      expires_at,
    })
  }

  pub async fn issue_service_token(
    &self,
    service_id: i32,
    service_name: &str,
  ) -> Result<TokenIssue, sqlx::Error> {
    let now = Self::now_epoch();
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "local_secret".to_string());
    let token = Self::generate_token_value(&secret, now);
    let payload = json!({
      "service_id": service_id,
      "service_name": service_name,
      "token_type": "service",
    });
    let expires_at = self.compute_service_expires_at(now);
    self.insert_token(&token, &payload, expires_at).await?;
    Ok(TokenIssue {
      token,
      expires_at,
    })
  }

  pub async fn delete_token(&self, token: &str) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query("DELETE FROM auth.tokens_cache WHERE token = $1")
      .bind(token)
      .execute(self.pool)
      .await?
      .rows_affected();
    Ok(rows > 0)
  }

  pub async fn delete_tokens_for_user(&self, user_id: i32) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query("DELETE FROM auth.tokens_cache WHERE payload ->> 'user_id' = $1")
      .bind(user_id.to_string())
      .execute(self.pool)
      .await?
      .rows_affected();
    Ok(rows)
  }

  pub async fn delete_access_cache(
    &self,
    user_id: i32,
    service_id: i32,
  ) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query(
      "DELETE FROM auth.permissions_cache
        WHERE token IN (
          SELECT token FROM auth.tokens_cache WHERE payload ->> 'user_id' = $1
        ) AND service_id = $2",
    )
    .bind(user_id.to_string())
    .bind(service_id)
    .execute(self.pool)
    .await?
    .rows_affected();
    Ok(rows)
  }

  pub async fn delete_access_cache_for_user(&self, user_id: i32) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query(
      "DELETE FROM auth.permissions_cache
        WHERE token IN (
          SELECT token FROM auth.tokens_cache WHERE payload ->> 'user_id' = $1
        )",
    )
      .bind(user_id.to_string())
      .execute(self.pool)
      .await?
      .rows_affected();
    Ok(rows)
  }

  pub async fn delete_access_cache_for_service(
    &self,
    service_id: i32,
  ) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query("DELETE FROM auth.permissions_cache WHERE service_id = $1")
    .bind(service_id)
    .execute(self.pool)
    .await?
    .rows_affected();
    Ok(rows)
  }

  pub async fn clear_access_cache(&self) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query("DELETE FROM auth.permissions_cache")
      .execute(self.pool)
      .await?
      .rows_affected();
    Ok(rows)
  }

  pub async fn load_access_cache(
    &self,
    token: &str,
    service_id: i32,
  ) -> Result<Option<AccessCacheRecord>, sqlx::Error> {
    sqlx::query_as::<_, AccessCacheRecord>(
      "SELECT permissions AS access_json, expires_at
        FROM auth.permissions_cache
        WHERE token = $1 AND service_id = $2",
    )
    .bind(token)
    .bind(service_id)
    .fetch_optional(self.pool)
    .await
  }

  pub async fn store_access_cache(
    &self,
    token: &str,
    service_id: i32,
    access_json: &Value,
    expires_at: i64,
  ) -> Result<(), sqlx::Error> {
    sqlx::query(
      "INSERT INTO auth.permissions_cache
        (token, service_id, permissions, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (token, service_id)
        DO UPDATE SET permissions = EXCLUDED.permissions,
          expires_at = EXCLUDED.expires_at",
    )
    .bind(token)
    .bind(service_id)
    .bind(access_json)
    .bind(expires_at)
    .execute(self.pool)
    .await?;
    Ok(())
  }

  pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
    let now = Self::now_epoch();
    let rows = sqlx::query(
      "DELETE FROM auth.tokens_cache
        WHERE expires_at < $1",
    )
      .bind(now)
      .execute(self.pool)
      .await?
      .rows_affected();
    let permissions_rows = sqlx::query(
      "DELETE FROM auth.permissions_cache
        WHERE expires_at < $1",
    )
    .bind(now)
    .execute(self.pool)
    .await?
    .rows_affected();
    Ok(rows + permissions_rows)
  }

  fn has_expired(&self, expires_at: i64, now: i64) -> bool {
    now >= expires_at
  }

  fn should_renew(&self, expires_at: i64, now: i64) -> bool {
    if self.config.renew_threshold_seconds <= 0 {
      return false;
    }
    expires_at - now <= self.config.renew_threshold_seconds
  }

  async fn validate_token_with_ttl(
    &self,
    token: &str,
    renew_if_needed: bool,
    ttl_seconds: i64,
  ) -> Result<TokenValidation, TokenError> {
    let mut record = match self.fetch_token(token).await? {
      Some(rec) => rec,
      None => return Err(TokenError::NotFound),
    };
    let now = Self::now_epoch();
    if self.has_expired(record.expires_at, now) {
      let _ = self.delete_token(token).await;
      return Err(TokenError::Expired);
    }

    let mut renewed = false;
    if renew_if_needed && self.should_renew(record.expires_at, now) {
      let new_expires_at = now + ttl_seconds;
      match self
        .touch_token(token, record.expires_at, new_expires_at)
        .await?
      {
        Some(updated) => {
          record = updated;
          renewed = true;
        }
        None => {
          if let Some(updated) = self.fetch_token(token).await? {
            if self.has_expired(updated.expires_at, now) {
              let _ = self.delete_token(token).await;
              return Err(TokenError::Expired);
            }
            record = updated;
          } else {
            return Err(TokenError::NotFound);
          }
        }
      }
    }

    let expires_at = record.expires_at;
    Ok(TokenValidation {
      record,
      renewed,
      expires_at,
    })
  }

  pub async fn validate_token(
    &self,
    token: &str,
    renew_if_needed: bool,
  ) -> Result<TokenValidation, TokenError> {
    self
      .validate_token_with_ttl(token, renew_if_needed, self.config.ttl_seconds)
      .await
  }

  pub async fn validate_service_token(
    &self,
    token: &str,
  ) -> Result<TokenValidation, TokenError> {
    self
      .validate_token_with_ttl(token, false, self.config.service_ttl_seconds)
      .await
  }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccessCacheRecord {
  pub access_json: Value,
  pub expires_at: i64,
}
