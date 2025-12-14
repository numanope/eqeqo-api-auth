use crate::auth::{TokenError, TokenManager, TokenValidation};
use crate::database::DB;
use httpageboy::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

// Generic response for errors
pub(super) fn error_response(status_code: StatusCode, message: &str) -> Response {
  Response {
    status: status_code.to_string(),
    content_type: "application/json".to_string(),
    content: json!({ "error": message }).to_string().into_bytes(),
  }
}

pub(super) fn error_response_with_detail(
  status_code: StatusCode,
  message: &str,
  detail: &str,
) -> Response {
  Response {
    status: status_code.to_string(),
    content_type: "application/json".to_string(),
    content: json!({ "error": message, "detail": detail })
      .to_string()
      .into_bytes(),
  }
}

fn extract_token(req: &Request) -> Option<String> {
  req
    .headers
    .iter()
    .find(|(key, _)| key.eq_ignore_ascii_case("token"))
    .map(|(_, value)| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

pub(super) fn unauthorized_response(message: &str) -> Response {
  let detail = match message {
    "missing_token_header" => "header token ausente o vacío; envía token: <valor> en cada petición",
    "invalid_token" => "token inválido o revocado; realiza login para obtener uno nuevo",
    "expired_token" => "token expirado; solicita un token nuevo iniciando sesión",
    "invalid_credentials" => "usuario o contraseña incorrectos",
    _ => "solicitud no autorizada",
  };
  error_response_with_detail(StatusCode::Unauthorized, message, detail)
}

fn current_epoch() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64
}

fn extract_ip(req: &Request) -> String {
  for header in ["x-forwarded-for", "x-real-ip", "remote-addr"] {
    if let Some((_, value)) = req
      .headers
      .iter()
      .find(|(key, _)| key.eq_ignore_ascii_case(header))
    {
      if let Some(first) = value.split(',').next() {
        let trimmed = first.trim();
        if !trimmed.is_empty() {
          return trimmed.to_string();
        }
      }
    }
  }
  "unknown".to_string()
}

pub(super) fn log_access(token: &str, req: &Request) {
  let endpoint = req.path.as_str();
  let ip = extract_ip(req);
  let timestamp = current_epoch();
  println!(
    "[access] token={} endpoint={} ts={} ip={}",
    token, endpoint, timestamp, ip
  );
}

async fn require_token(
  req: &Request,
  renew: bool,
) -> Result<(DB, TokenValidation, String), Response> {
  let token = match extract_token(req) {
    Some(value) => value,
    None => return Err(unauthorized_response("missing_token_header")),
  };
  let db = match DB::new().await {
    Ok(db) => db,
    Err(_) => {
      return Err(error_response(
        StatusCode::InternalServerError,
        "db_unavailable",
      ));
    }
  };
  let manager = TokenManager::new(db.pool());
  match manager.validate_token(&token, renew).await {
    Ok(validation) => {
      log_access(&token, req);
      Ok((db, validation, token))
    }
    Err(TokenError::NotFound) => Err(unauthorized_response("invalid_token")),
    Err(TokenError::Expired) => Err(unauthorized_response("expired_token")),
    Err(TokenError::Database(_)) => Err(error_response(
      StatusCode::InternalServerError,
      "token_validation_failed",
    )),
  }
}

pub(super) async fn require_token_with_renew(
  req: &Request,
) -> Result<(DB, TokenValidation, String), Response> {
  require_token(req, true).await
}

pub(super) async fn get_db_connection() -> Result<DB, Response> {
  match DB::new().await {
    Ok(db) => Ok(db),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "db_unavailable",
    )),
  }
}

pub(super) async fn with_auth<F, Fut>(req: &Request, renew: bool, action: F) -> Response
where
  F: FnOnce(&Request, DB, TokenValidation, String) -> Fut,
  Fut: Future<Output = Response>,
{
  match require_token(req, renew).await {
    Ok((db, validation, token)) => action(req, db, validation, token).await,
    Err(response) => response,
  }
}

pub(super) async fn with_auth_no_renew<F, Fut>(req: &Request, action: F) -> Response
where
  F: FnOnce(&Request, DB, TokenValidation, String) -> Fut,
  Fut: Future<Output = Response>,
{
  with_auth(req, false, action).await
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FlexibleId {
  Int(i32),
  Str(String),
}

impl FlexibleId {
  fn parse_int(&self) -> Option<i32> {
    match self {
      FlexibleId::Int(value) => Some(*value),
      FlexibleId::Str(raw) => raw.trim().parse::<i32>().ok(),
    }
  }

  fn as_str(&self) -> Option<&str> {
    match self {
      FlexibleId::Str(value) => Some(value.as_str()),
      _ => None,
    }
  }
}

fn extract_digits(value: &str) -> Option<i32> {
  let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
  if digits.is_empty() {
    None
  } else {
    digits.parse::<i32>().ok()
  }
}

impl From<&str> for FlexibleId {
  fn from(value: &str) -> Self {
    value
      .trim()
      .parse::<i32>()
      .map(FlexibleId::Int)
      .unwrap_or_else(|_| FlexibleId::Str(value.trim().to_string()))
  }
}

impl From<String> for FlexibleId {
  fn from(value: String) -> Self {
    FlexibleId::from(value.as_str())
  }
}

pub(super) async fn resolve_service_id(
  db: &DB,
  identifier: &FlexibleId,
  create_if_missing: bool,
) -> Result<i32, Response> {
  if let Some(id) = identifier.parse_int() {
    return Ok(id);
  }
  let name = identifier
    .as_str()
    .map(|s| s.trim())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| error_response(StatusCode::BadRequest, "invalid_service_id"))?;

  match sqlx::query_scalar::<_, i32>("SELECT id FROM auth.services WHERE name = $1")
    .bind(name)
    .fetch_optional(db.pool())
    .await
  {
    Ok(Some(id)) => Ok(id),
    Ok(None) if create_if_missing => match sqlx::query_scalar::<_, i32>(
      "INSERT INTO auth.services (name) VALUES ($1)
        ON CONFLICT (name) DO NOTHING
        RETURNING id",
    )
    .bind(name)
    .fetch_optional(db.pool())
    .await
    {
      Ok(Some(id)) => Ok(id),
      Ok(None) => sqlx::query_scalar::<_, i32>("SELECT id FROM auth.services WHERE name = $1")
        .bind(name)
        .fetch_one(db.pool())
        .await
        .map_err(|_| error_response(StatusCode::InternalServerError, "resolve_service_failed")),
      Err(_) => Err(error_response(
        StatusCode::InternalServerError,
        "resolve_service_failed",
      )),
    },
    Ok(None) => Err(error_response(StatusCode::BadRequest, "invalid_service_id")),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "resolve_service_failed",
    )),
  }
}

pub(super) async fn resolve_person_id(db: &DB, identifier: &FlexibleId) -> Result<i32, Response> {
  if let Some(id) = identifier.parse_int() {
    return Ok(id);
  }
  if let Some(str_value) = identifier.as_str() {
    let trimmed = str_value.trim();
    if trimmed.starts_with("person-") {
      if let Some(id) = extract_digits(trimmed) {
        return Ok(id);
      }
    }
    let username = trimmed;
    if username.is_empty() {
      return Err(error_response(StatusCode::BadRequest, "invalid_person_id"));
    }
    return match sqlx::query_scalar::<_, i32>(
      "SELECT id FROM auth.person WHERE username = $1 AND removed_at IS NULL",
    )
    .bind(username)
    .fetch_optional(db.pool())
    .await
    {
      Ok(Some(id)) => Ok(id),
      Ok(None) => Err(error_response(StatusCode::BadRequest, "person_not_found")),
      Err(_) => Err(error_response(
        StatusCode::InternalServerError,
        "resolve_person_failed",
      )),
    };
  }
  Err(error_response(StatusCode::BadRequest, "invalid_person_id"))
}

mod permissions;
mod relations;
mod roles;
mod services;
mod users;

pub use permissions::*;
pub use relations::*;
pub use roles::*;
pub use services::*;
pub use users::*;
