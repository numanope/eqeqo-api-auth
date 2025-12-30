use crate::auth::TokenManager;
use bcrypt::{hash, verify, DEFAULT_COST};
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
  FlexibleId, error_response, get_db_connection, load_roles_and_permissions, log_access,
  require_service_token, require_token_with_renew, unauthorized_response, with_auth,
  with_auth_no_renew,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Basic endpoints
pub async fn home(_req: &Request) -> Response {
  Response {
    status: StatusCode::Ok.to_string(),
    content_type: "text/html".to_string(),
    content: "<h1>Welcome to the Auth API</h1>".as_bytes().to_vec(),
  }
}

#[derive(Deserialize)]
pub struct LoginPayload {
  username: String,
  password: String,
}

#[derive(sqlx::FromRow)]
struct AuthUser {
  id: i32,
  username: String,
  password_hash: String,
  name: String,
}

fn hash_password(password: &str) -> Result<String, Response> {
  hash(password, DEFAULT_COST)
    .map_err(|_| error_response(StatusCode::InternalServerError, "hash_password_failed"))
}

pub async fn login(req: &Request) -> Response {
  let payload: LoginPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let db = match get_db_connection().await {
    Ok(db) => db,
    Err(response) => return response,
  };

  let user = match sqlx::query_as::<_, AuthUser>(
    "SELECT id, username, password_hash, name FROM auth.person WHERE username = $1 AND removed_at IS NULL",
  )
  .bind(&payload.username)
  .fetch_optional(db.pool())
  .await
  {
    Ok(Some(user)) => user,
    Ok(None) => return unauthorized_response("invalid_credentials"),
    Err(_) => {
      return error_response(
        StatusCode::InternalServerError,
        "login_lookup_failed",
      );
    }
  };

  match verify(&payload.password, &user.password_hash) {
    Ok(true) => {}
    _ => return unauthorized_response("invalid_credentials"),
  }

  let user_payload = json!({
    "user_id": user.id,
    "username": user.username,
    "name": user.name,
  });

  let manager = TokenManager::new(db.pool());
  let issued = match manager.issue_token(user_payload.clone()).await {
    Ok(issue) => issue,
    Err(_) => {
      return error_response(StatusCode::InternalServerError, "login_issue_failed");
    }
  };

  log_access(&issued.token, req);

  Response {
    status: StatusCode::Ok.to_string(),
    content_type: "application/json".to_string(),
    content: json!({
      "token": issued.token,
      "expires_at": issued.expires_at,
      "payload": user_payload,
    })
    .to_string()
    .into_bytes(),
  }
}

pub async fn logout(req: &Request) -> Response {
  with_auth_no_renew(req, |_req, db, _, token| async move {
    let manager = TokenManager::new(db.pool());
    match manager.delete_token(&token).await {
      Ok(_) => Response {
        status: StatusCode::Ok.to_string(),
        content_type: "application/json".to_string(),
        content: json!({ "status": "logged_out" }).to_string().into_bytes(),
      },
      Err(_) => error_response(StatusCode::InternalServerError, "logout_failed"),
    }
  })
  .await
}

pub async fn profile(req: &Request) -> Response {
  with_auth(req, true, |_req, _db, validation, _token| async move {
    let payload = validation.record.payload.clone();
    Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({
        "payload": payload,
        "renewed": validation.renewed,
        "expires_at": validation.expires_at,
      })
      .to_string()
      .into_bytes(),
    }
  })
  .await
}

pub async fn check_token(req: &Request) -> Response {
  #[derive(Deserialize)]
  struct CheckTokenRequest {
    user_id: Option<FlexibleId>,
  }

  let body_checks: Option<CheckTokenRequest> = if req.body.trim().is_empty() {
    None
  } else {
    serde_json::from_slice(req.body.as_bytes()).ok()
  };

  let (db, validation, _token) = match require_token_with_renew(req).await {
    Ok(result) => result,
    Err(response) => return response,
  };

  let (_service_validation, _service_token, service_id) =
    match require_service_token(&db, req).await {
      Ok(result) => result,
      Err(response) => return response,
    };

  let payload = validation.record.payload.clone();
  let token_user_id = payload
    .get("user_id")
    .and_then(|value| value.as_i64())
    .map(|v| v as i32);

  if let Some(checks) = &body_checks {
    if let (Some(expected), Some(actual)) = (
      checks.user_id.as_ref().and_then(|id| id.parse_int()),
      token_user_id,
    ) {
      if expected != actual {
        return unauthorized_response("invalid_token");
      }
    }
  }

  let user_id = match token_user_id {
    Some(id) => id,
    None => return unauthorized_response("invalid_token"),
  };

  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64;

  let manager = TokenManager::new(db.pool());
  let cached_access = match manager.load_access_cache(user_id, service_id).await {
    Ok(Some(cache)) if cache.expires_at > now => Some(cache.access_json),
    Ok(_) => None,
    Err(_) => {
      return error_response(StatusCode::InternalServerError, "load_access_cache_failed");
    }
  };

  let access_json = if let Some(access) = cached_access {
    access
  } else {
    let (roles, permissions) = match load_roles_and_permissions(&db, user_id, service_id).await {
      Ok(result) => result,
      Err(response) => return response,
    };
    let expires_at = now + manager.ttl();
    let access = json!({
      "user_id": user_id,
      "service_id": service_id,
      "roles": roles,
      "permissions": permissions,
      "scopes": [],
      "expires_at": expires_at,
    });
    if let Err(_) = manager
      .store_access_cache(user_id, service_id, &access, now, expires_at)
      .await
    {
      return error_response(StatusCode::InternalServerError, "store_access_cache_failed");
    }
    access
  };

  Response {
    status: StatusCode::Ok.to_string(),
    content_type: "application/json".to_string(),
    content: json!({
      "valid": true,
      "access": access_json,
      "renewed": validation.renewed,
      "expires_at": validation.expires_at,
    })
    .to_string()
    .into_bytes(),
  }
}

// User Handlers
#[derive(Serialize, sqlx::FromRow)]
pub struct User {
  id: i32,
  username: String,
  name: String,
}

#[derive(Deserialize)]
pub struct CreateUserPayload {
  username: String,
  password_hash: String,
  name: String,
  person_type: String,   // N or J
  document_type: String, // DNI, CE, or RUC
  document_number: String,
}

pub async fn create_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let is_blank = |value: &str| value.trim().is_empty();
  if is_blank(&payload.username)
    || is_blank(&payload.password_hash)
    || is_blank(&payload.name)
    || is_blank(&payload.person_type)
    || is_blank(&payload.document_type)
    || is_blank(&payload.document_number)
  {
    return error_response(StatusCode::BadRequest, "invalid_request_body");
  }

  // Note: In a real app, you'd want to handle these enums more gracefully.
  let person_type: auth_types::PersonType =
    match serde_json::from_str(&format!("\"{}\"", payload.person_type.trim())) {
      Ok(value) => value,
      Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
    };
  let document_type: auth_types::DocumentType =
    match serde_json::from_str(&format!("\"{}\"", payload.document_type.trim())) {
      Ok(value) => value,
      Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
    };

  let password_hash = match hash_password(&payload.password_hash) {
    Ok(hashed) => hashed,
    Err(resp) => return resp,
  };

  match sqlx::query_as::<_, User>(
    "SELECT id, username, name FROM auth.create_person($1, $2, $3, $4, $5, $6)",
  )
  .bind(payload.username)
  .bind(password_hash)
  .bind(payload.name)
  .bind(person_type)
  .bind(document_type)
  .bind(payload.document_number)
  .fetch_one(db.pool())
  .await
  {
    Ok(user) => Response {
      status: StatusCode::Created.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&user).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "create_user_failed"),
  }
}

pub async fn list_people(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, User>("SELECT id, username, name FROM auth.list_people()")
    .fetch_all(db.pool())
    .await
  {
    Ok(users) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&users).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "list_users_failed"),
  }
}

pub async fn get_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_user_id"),
  };
  match sqlx::query_as::<_, User>("SELECT id, username, name FROM auth.get_person($1)")
    .bind(id)
    .fetch_optional(db.pool())
    .await
  {
    Ok(Some(user)) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&user).unwrap(),
    },
    Ok(None) => error_response(StatusCode::NotFound, "user_not_found"),
    Err(_) => error_response(StatusCode::InternalServerError, "get_user_failed"),
  }
}

#[derive(Deserialize)]
pub struct UpdateUserPayload {
  username: Option<String>,
  password_hash: Option<String>,
  name: Option<String>,
}

pub async fn update_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_user_id"),
  };
  let payload: UpdateUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let hashed_password = match payload.password_hash {
    Some(ref pw) => match hash_password(pw) {
      Ok(hashed) => Some(hashed),
      Err(resp) => return resp,
    },
    None => None,
  };

  match sqlx::query("CALL auth.update_person($1, $2, $3, $4)")
    .bind(id)
    .bind(payload.username)
    .bind(hashed_password)
    .bind(payload.name)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "update_user_failed"),
  }
}

pub async fn delete_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_user_id"),
  };
  let manager = TokenManager::new(db.pool());
  match sqlx::query("CALL auth.delete_person($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => match manager.delete_tokens_for_user(id).await {
      Ok(revoked) => Response {
        status: StatusCode::Ok.to_string(),
        content_type: "application/json".to_string(),
        content: json!({
          "status": "user_deleted",
          "user_id": id,
          "revoked_tokens": revoked
        })
        .to_string()
        .into_bytes(),
      },
      Err(_) => error_response(StatusCode::InternalServerError, "user_token_cleanup_failed"),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "delete_user_failed"),
  }
}

// These are needed for the create_person handler to deserialize the enums
mod auth_types {
  use serde::Deserialize;
  #[derive(Debug, Deserialize, sqlx::Type)]
  #[sqlx(type_name = "person_type", rename_all = "UPPERCASE")]
  pub enum PersonType {
    N,
    J,
  }

  #[derive(Debug, Deserialize, sqlx::Type)]
  #[sqlx(type_name = "document_type", rename_all = "UPPERCASE")]
  pub enum DocumentType {
    DNI,
    CE,
    RUC,
  }
}
