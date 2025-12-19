use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenRecord {
  pub token: String,
  pub payload: Value,
  pub modified_at: i64,
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
  pub ttl_seconds: i64,
  pub renew_threshold_seconds: i64,
}

impl TokenConfig {
  pub fn load() -> Self {
    let ttl_seconds = env::var("TOKEN_TTL_SECONDS")
      .ok()
      .and_then(|v| v.parse::<i64>().ok())
      .unwrap_or(300);
    let renew_threshold_seconds = env::var("TOKEN_RENEW_THRESHOLD_SECONDS")
      .ok()
      .and_then(|v| v.parse::<i64>().ok())
      .unwrap_or(30);
    Self {
      ttl_seconds,
      renew_threshold_seconds,
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
    modified_at: i64,
  ) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO auth.tokens_cache (token, payload, modified_at) VALUES ($1, $2, $3)")
      .bind(token)
      .bind(payload)
      .bind(modified_at)
      .execute(self.pool)
      .await?;
    Ok(())
  }

  async fn fetch_token(&self, token: &str) -> Result<Option<TokenRecord>, sqlx::Error> {
    sqlx::query_as::<_, TokenRecord>(
      "SELECT token, payload, modified_at FROM auth.tokens_cache WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(self.pool)
    .await
  }

  async fn touch_token(
    &self,
    token: &str,
    previous_modified_at: i64,
    new_modified_at: i64,
  ) -> Result<Option<TokenRecord>, sqlx::Error> {
    sqlx::query_as::<_, TokenRecord>(
      "UPDATE auth.tokens_cache SET modified_at = $1 WHERE token = $2 AND modified_at = $3 RETURNING token, payload, modified_at",
    )
    .bind(new_modified_at)
    .bind(token)
    .bind(previous_modified_at)
    .fetch_optional(self.pool)
    .await
  }

  fn compute_expires_at(&self, modified_at: i64) -> i64 {
    modified_at + self.config.ttl_seconds
  }

  pub async fn issue_token(&self, payload: Value) -> Result<TokenIssue, sqlx::Error> {
    let now = Self::now_epoch();
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "local_secret".to_string());
    let token = Self::generate_token_value(&secret, now);
    self.insert_token(&token, &payload, now).await?;
    Ok(TokenIssue {
      token,
      expires_at: self.compute_expires_at(now),
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

  pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
    let ttl = self.config.ttl_seconds.max(1);
    let cutoff = Self::now_epoch() - ttl;
    let rows = sqlx::query("DELETE FROM auth.tokens_cache WHERE modified_at < $1")
      .bind(cutoff)
      .execute(self.pool)
      .await?
      .rows_affected();
    Ok(rows)
  }

  fn has_expired(&self, modified_at: i64, now: i64) -> bool {
    now - modified_at > self.config.ttl_seconds
  }

  fn should_renew(&self, modified_at: i64, now: i64) -> bool {
    if self.config.renew_threshold_seconds <= 0 {
      return false;
    }
    let expires_at = self.compute_expires_at(modified_at);
    expires_at - now <= self.config.renew_threshold_seconds
  }

  pub async fn validate_token(
    &self,
    token: &str,
    renew_if_needed: bool,
  ) -> Result<TokenValidation, TokenError> {
    let mut record = match self.fetch_token(token).await? {
      Some(rec) => rec,
      None => return Err(TokenError::NotFound),
    };
    let now = Self::now_epoch();
    if self.has_expired(record.modified_at, now) {
      let _ = self.delete_token(token).await;
      return Err(TokenError::Expired);
    }

    let mut renewed = false;
    if renew_if_needed && self.should_renew(record.modified_at, now) {
      match self.touch_token(token, record.modified_at, now).await? {
        Some(updated) => {
          record = updated;
          renewed = true;
        }
        None => {
          if let Some(updated) = self.fetch_token(token).await? {
            if self.has_expired(updated.modified_at, now) {
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

    let expires_at = self.compute_expires_at(record.modified_at);

    Ok(TokenValidation {
      record,
      renewed,
      expires_at,
    })
  }
}
