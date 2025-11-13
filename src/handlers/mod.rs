use crate::auth::{TokenError, TokenManager, TokenValidation};
use crate::database::DB;
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

// Generic response for errors
fn error_response(status_code: StatusCode, message: &str) -> Response {
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

fn unauthorized_response(message: &str) -> Response {
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

fn log_access(token: &str, req: &Request) {
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
    None => return Err(unauthorized_response("Missing token header")),
  };
  let db = match DB::new().await {
    Ok(db) => db,
    Err(_) => {
      return Err(error_response(
        StatusCode::InternalServerError,
        "Failed to connect to database",
      ));
    }
  };
  let manager = TokenManager::new(db.pool());
  match manager.validate_token(&token, renew).await {
    Ok(validation) => {
      log_access(&token, req);
      Ok((db, validation, token))
    }
    Err(TokenError::NotFound) => Err(unauthorized_response("Invalid token")),
    Err(TokenError::Expired) => Err(unauthorized_response("Expired token")),
    Err(TokenError::Database(_)) => Err(error_response(
      StatusCode::InternalServerError,
      "Failed to validate token",
    )),
  }
}

async fn require_token_without_renew(
  req: &Request,
) -> Result<(DB, TokenValidation, String), Response> {
  require_token(req, false).await
}

async fn get_db_connection() -> Result<DB, Response> {
  match DB::new().await {
    Ok(db) => Ok(db),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "Failed to connect to database",
    )),
  }
}

async fn with_auth<F, Fut>(req: &Request, renew: bool, action: F) -> Response
where
  F: FnOnce(&Request, DB, TokenValidation, String) -> Fut,
  Fut: Future<Output = Response>,
{
  match require_token(req, renew).await {
    Ok((db, validation, token)) => action(req, db, validation, token).await,
    Err(response) => response,
  }
}

async fn with_auth_no_renew<F, Fut>(req: &Request, action: F) -> Response
where
  F: FnOnce(&Request, DB, TokenValidation, String) -> Fut,
  Fut: Future<Output = Response>,
{
  with_auth(req, false, action).await
}

// Home
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

pub async fn login(req: &Request) -> Response {
  let payload: LoginPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
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
    Ok(None) => return unauthorized_response("Invalid credentials"),
    Err(_) => {
      return error_response(
        StatusCode::InternalServerError,
        "Failed to query user credentials",
      );
    }
  };

  if user.password_hash != payload.password {
    return unauthorized_response("Invalid credentials");
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
      return error_response(
        StatusCode::InternalServerError,
        "Failed to create login token",
      );
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
      Err(_) => error_response(StatusCode::InternalServerError, "Failed to revoke token"),
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
  with_auth(req, true, |_req, _db, validation, _token| async move {
    let payload = validation.record.payload.clone();
    Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({
        "valid": true,
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
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };

  // Note: In a real app, you'd want to handle these enums more gracefully.
  let person_type: auth_types::PersonType =
    serde_json::from_str(&format!("\"{}\"", payload.person_type))
      .unwrap_or(auth_types::PersonType::N);
  let document_type: auth_types::DocumentType =
    serde_json::from_str(&format!("\"{}\"", payload.document_type))
      .unwrap_or(auth_types::DocumentType::DNI);

  match sqlx::query_as::<_, User>(
    "SELECT id, username, name FROM auth.create_person($1, $2, $3, $4, $5, $6)",
  )
  .bind(payload.username)
  .bind(payload.password_hash)
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
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to create user"),
  }
}

pub async fn list_people(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
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
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch users"),
  }
}

pub async fn get_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid user ID"),
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
    Ok(None) => error_response(StatusCode::NotFound, "User not found"),
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch user"),
  }
}

#[derive(Deserialize)]
pub struct UpdateUserPayload {
  username: Option<String>,
  password_hash: Option<String>,
  name: Option<String>,
}

pub async fn update_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid user ID"),
  };
  let payload: UpdateUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.update_person($1, $2, $3, $4)")
    .bind(id)
    .bind(payload.username)
    .bind(payload.password_hash)
    .bind(payload.name)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to update user"),
  }
}

pub async fn delete_user(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid user ID"),
  };
  let manager = TokenManager::new(db.pool());
  match sqlx::query("CALL auth.delete_person($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => match manager.delete_tokens_for_user(id).await {
      Ok(_) => Response {
        status: StatusCode::NoContent.to_string(),
        content_type: "application/json".to_string(),
        content: Vec::new(),
      },
      Err(_) => error_response(
        StatusCode::InternalServerError,
        "Failed to remove user tokens",
      ),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to delete user"),
  }
}

// Service Handlers
#[derive(Serialize, sqlx::FromRow)]
pub struct Service {
  id: i32,
  name: String,
  description: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateServicePayload {
  name: String,
  description: Option<String>,
}

pub async fn create_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateServicePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query_as::<_, Service>("SELECT * FROM auth.create_service($1, $2)")
    .bind(payload.name)
    .bind(payload.description)
    .fetch_one(db.pool())
    .await
  {
    Ok(service) => Response {
      status: StatusCode::Created.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&service).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to create service"),
  }
}

pub async fn list_services(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Service>("SELECT * FROM auth.list_services()")
    .fetch_all(db.pool())
    .await
  {
    Ok(services) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&services).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch services"),
  }
}

#[derive(Deserialize)]
pub struct UpdateServicePayload {
  name: Option<String>,
  description: Option<String>,
}

pub async fn update_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid service ID"),
  };
  let payload: UpdateServicePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.update_service($1, $2, $3)")
    .bind(id)
    .bind(payload.name)
    .bind(payload.description)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to update service"),
  }
}

pub async fn delete_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid service ID"),
  };
  match sqlx::query("CALL auth.delete_service($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to delete service"),
  }
}

// Role Handlers
#[derive(Serialize, sqlx::FromRow)]
pub struct Role {
  id: i32,
  name: String,
}

#[derive(Deserialize)]
pub struct CreateRolePayload {
  name: String,
}

pub async fn create_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.create_role($1)")
    .bind(payload.name)
    .fetch_one(db.pool())
    .await
  {
    Ok(role) => Response {
      status: StatusCode::Created.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&role).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to create role"),
  }
}

pub async fn list_roles(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_roles()")
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch roles"),
  }
}

pub async fn get_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.get_role($1)")
    .bind(id)
    .fetch_optional(db.pool())
    .await
  {
    Ok(Some(role)) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&role).unwrap(),
    },
    Ok(None) => error_response(StatusCode::NotFound, "Role not found"),
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch role"),
  }
}

#[derive(Deserialize)]
pub struct UpdateRolePayload {
  name: String,
}

pub async fn update_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  let payload: UpdateRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.update_role($1, $2)")
    .bind(id)
    .bind(payload.name)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(err) => {
      eprintln!("[handler-error] update_role: {}", err);
      error_response(StatusCode::InternalServerError, "Failed to update role")
    }
  }
}

pub async fn delete_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query("CALL auth.delete_role($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to delete role"),
  }
}

// Permission Handlers
#[derive(Serialize, sqlx::FromRow)]
pub struct Permission {
  id: i32,
  name: String,
}

#[derive(Deserialize)]
pub struct CreatePermissionPayload {
  name: String,
}

pub async fn create_permission(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreatePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query_as::<_, Permission>("SELECT * FROM auth.create_permission($1)")
    .bind(payload.name)
    .fetch_one(db.pool())
    .await
  {
    Ok(permission) => Response {
      status: StatusCode::Created.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&permission).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to create permission",
    ),
  }
}

pub async fn list_permissions(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Permission>("SELECT * FROM auth.list_permissions()")
    .fetch_all(db.pool())
    .await
  {
    Ok(permissions) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&permissions).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch permissions",
    ),
  }
}

#[derive(Deserialize)]
pub struct UpdatePermissionPayload {
  name: String,
}

pub async fn update_permission(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid permission ID"),
  };
  let payload: UpdatePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.update_permission($1, $2)")
    .bind(id)
    .bind(payload.name)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(err) => {
      eprintln!("[handler-error] update_permission: {}", err);
      error_response(
        StatusCode::InternalServerError,
        "Failed to update permission",
      )
    }
  }
}

pub async fn delete_permission(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid permission ID"),
  };
  match sqlx::query("CALL auth.delete_permission($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to delete permission",
    ),
  }
}

// Relationship Handlers
#[derive(Deserialize)]
pub struct RolePermissionPayload {
  role_id: i32,
  permission_id: i32,
}

pub async fn assign_permission_to_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: RolePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.assign_permission_to_role($1, $2)")
    .bind(payload.role_id)
    .bind(payload.permission_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to assign permission to role",
    ),
  }
}

pub async fn remove_permission_from_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: RolePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.remove_permission_from_role($1, $2)")
    .bind(payload.role_id)
    .bind(payload.permission_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to remove permission from role",
    ),
  }
}

pub async fn list_role_permissions(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query_as::<_, Permission>("SELECT * FROM auth.list_role_permissions($1)")
    .bind(id)
    .fetch_all(db.pool())
    .await
  {
    Ok(permissions) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&permissions).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch role permissions",
    ),
  }
}

#[derive(Deserialize)]
pub struct ServiceRolePayload {
  service_id: i32,
  role_id: i32,
}

pub async fn assign_role_to_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: ServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.assign_role_to_service($1, $2)")
    .bind(payload.service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to assign role to service",
    ),
  }
}

pub async fn remove_role_from_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: ServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.remove_role_from_service($1, $2)")
    .bind(payload.service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to remove role from service",
    ),
  }
}

pub async fn list_service_roles(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid service ID"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_service_roles($1)")
    .bind(id)
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch service roles",
    ),
  }
}

#[derive(Deserialize)]
pub struct PersonServiceRolePayload {
  person_id: i32,
  service_id: i32,
  role_id: i32,
}

pub async fn assign_role_to_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: PersonServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.assign_role_to_person_in_service($1, $2, $3)")
    .bind(payload.person_id)
    .bind(payload.service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to assign role to person in service",
    ),
  }
}

pub async fn remove_role_from_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: PersonServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.remove_role_from_person_in_service($1, $2, $3)")
    .bind(payload.person_id)
    .bind(payload.service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to remove role from person in service",
    ),
  }
}

pub async fn list_person_roles_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id: i32 = match req.params.get("person_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid person ID"),
  };
  let service_id: i32 = match req.params.get("service_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid service ID"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_person_roles_in_service($1, $2)")
    .bind(person_id)
    .bind(service_id)
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch person roles in service",
    ),
  }
}

pub async fn list_persons_with_role_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let service_id: i32 = match req.params.get("service_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid service ID"),
  };
  let role_id: i32 = match req.params.get("role_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query_as::<_, User>(
    "SELECT id, username, name FROM auth.list_persons_with_role_in_service($1, $2)",
  )
  .bind(service_id)
  .bind(role_id)
  .fetch_all(db.pool())
  .await
  {
    Ok(users) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&users).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch persons with role in service",
    ),
  }
}

#[derive(Deserialize)]
pub struct CheckPermissionPayload {
  person_id: i32,
  service_id: i32,
  permission_name: String,
}

pub async fn check_person_permission_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CheckPermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(err) => {
      eprintln!(
        "[parse-error] check_permission body='{}' err={}",
        req.body.replace('\n', "\\n"),
        err
      );
      return error_response(StatusCode::BadRequest, "Invalid request body");
    }
  };
  match sqlx::query_scalar::<_, bool>(
    "SELECT * FROM auth.check_person_permission_in_service($1, $2, $3)",
  )
  .bind(payload.person_id)
  .bind(payload.service_id)
  .bind(payload.permission_name)
  .fetch_one(db.pool())
  .await
  {
    Ok(has_permission) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "has_permission": has_permission })
        .to_string()
        .into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to check permission",
    ),
  }
}

pub async fn list_services_of_person(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id: i32 = match req.params.get("person_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid person ID"),
  };
  match sqlx::query_as::<_, Service>(
    "SELECT id, name, NULL as description FROM auth.list_services_of_person($1)",
  )
  .bind(person_id)
  .fetch_all(db.pool())
  .await
  {
    Ok(services) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&services).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "Failed to fetch services of person",
    ),
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
