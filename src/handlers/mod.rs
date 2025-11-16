use crate::auth::{TokenError, TokenManager, TokenValidation};
use crate::database::DB;
use httpageboy::{Request, Response, StatusCode};
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

fn extract_token(req: &Request) -> Option<String> {
  req
    .headers
    .iter()
    .find(|(key, _)| key.eq_ignore_ascii_case("token"))
    .map(|(_, value)| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

pub(super) fn unauthorized_response(message: &str) -> Response {
  error_response(StatusCode::Unauthorized, message)
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

pub(super) async fn require_token_without_renew(
  req: &Request,
) -> Result<(DB, TokenValidation, String), Response> {
  require_token(req, false).await
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
