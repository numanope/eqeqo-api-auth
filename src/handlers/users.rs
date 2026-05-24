use crate::auth::TokenManager;
use crate::responses::{json_response, json_response_value, response_with_body};
use bcrypt::{DEFAULT_COST, hash, verify};
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
  FlexibleId, error_response, extract_service_token, get_db_connection, load_roles_and_permissions,
  log_access, require_token_with_renew, require_token_with_renew_no_log, resolve_business_id,
  unauthorized_response, with_auth, with_auth_no_renew,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Basic endpoints
pub async fn home(_req: &Request) -> Response {
  response_with_body(
    StatusCode::Ok,
    "text/html",
    "<h1>Welcome to the Auth API</h1>".as_bytes().to_vec(),
  )
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

#[derive(Deserialize, Default)]
struct SettingsContextPayload {
  business_id: Option<FlexibleId>,
  app_id: Option<String>,
}

#[derive(Deserialize)]
struct SettingsPatchPayload {
  business_id: FlexibleId,
  app_id: String,
  settings_patch: serde_json::Value,
}

#[derive(Serialize, sqlx::FromRow)]
struct UserBusiness {
  id: i32,
  name: String,
  legal_name: Option<String>,
  document_type: Option<String>,
  document_number: Option<String>,
  status: bool,
}

fn header_value(req: &Request, name: &str) -> Option<String> {
  req
    .headers
    .iter()
    .find(|(key, _)| key.eq_ignore_ascii_case(name))
    .map(|(_, value)| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

fn normalize_app_id(value: Option<String>) -> Result<Option<String>, Response> {
  match value
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty())
  {
    Some(app_id) => Ok(Some(app_id)),
    None => Ok(None),
  }
}

fn settings_context_from_headers(req: &Request) -> SettingsContextPayload {
  SettingsContextPayload {
    business_id: header_value(req, "business-id").map(FlexibleId::from),
    app_id: header_value(req, "app-id"),
  }
}

async fn ensure_business_user(
  db: &crate::database::DB,
  business_id: i32,
  user_id: i32,
) -> Result<(), Response> {
  match sqlx::query_scalar::<_, bool>(
    "SELECT EXISTS (
      SELECT 1
      FROM auth.business_users bu
      JOIN auth.businesses b ON b.id = bu.business_id
      WHERE bu.business_id = $1
        AND bu.person_id = $2
        AND bu.status = TRUE
        AND bu.removed_at IS NULL
        AND b.status = TRUE
        AND b.removed_at IS NULL
    )",
  )
  .bind(business_id)
  .bind(user_id)
  .fetch_one(db.pool())
  .await
  {
    Ok(true) => Ok(()),
    Ok(false) => Err(error_response(
      StatusCode::Forbidden,
      "invalid_business_membership",
    )),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "business_membership_check_failed",
    )),
  }
}

async fn list_user_businesses(
  db: &crate::database::DB,
  user_id: i32,
) -> Result<Vec<UserBusiness>, Response> {
  match sqlx::query_as::<_, UserBusiness>(
    "SELECT b.id, b.name, b.legal_name, b.document_type::text, b.document_number, b.status
      FROM auth.businesses b
      JOIN auth.business_users bu ON bu.business_id = b.id
      WHERE bu.person_id = $1
        AND bu.status = TRUE
        AND bu.removed_at IS NULL
        AND b.status = TRUE
        AND b.removed_at IS NULL
      ORDER BY b.name, b.id",
  )
  .bind(user_id)
  .fetch_all(db.pool())
  .await
  {
    Ok(businesses) => Ok(businesses),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "list_my_businesses_failed",
    )),
  }
}

async fn load_user_app_settings(
  db: &crate::database::DB,
  user_id: i32,
  context: SettingsContextPayload,
) -> Result<Option<serde_json::Value>, Response> {
  let has_business = context.business_id.is_some();
  let app_id = normalize_app_id(context.app_id)?;
  if !has_business && app_id.is_none() {
    return Ok(None);
  }
  let Some(app_id) = app_id else {
    return Err(error_response(StatusCode::BadRequest, "missing_app_id"));
  };
  let business_id = resolve_business_id(db, context.business_id.as_ref()).await?;
  ensure_business_user(db, business_id, user_id).await?;

  match sqlx::query_scalar::<_, String>(
    "SELECT COALESCE(
      (
        SELECT settings::text
        FROM auth.user_app_settings
        WHERE business_id = $1 AND user_id = $2 AND app_id = $3
      ),
      '{}'::text
    )",
  )
  .bind(business_id)
  .bind(user_id)
  .bind(&app_id)
  .fetch_one(db.pool())
  .await
  {
    Ok(raw) => serde_json::from_str(&raw)
      .map(Some)
      .map_err(|_| error_response(StatusCode::InternalServerError, "load_settings_failed")),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "load_settings_failed",
    )),
  }
}

async fn add_settings_to_response(
  response: &mut serde_json::Value,
  db: &crate::database::DB,
  user_id: i32,
  context: SettingsContextPayload,
) -> Result<(), Response> {
  if let Some(settings) = load_user_app_settings(db, user_id, context).await? {
    response["settings"] = settings;
  }
  Ok(())
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
  if !crate::is_test_mode() {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs() as i64;
    let existing_token = match sqlx::query_as::<_, (String, i64)>(
      "SELECT token, expires_at FROM auth.tokens_cache
        WHERE payload ->> 'user_id' = $1 AND expires_at > $2
        ORDER BY expires_at DESC
        LIMIT 1",
    )
    .bind(user.id.to_string())
    .bind(now)
    .fetch_optional(db.pool())
    .await
    {
      Ok(token) => token,
      Err(_) => {
        return error_response(StatusCode::InternalServerError, "login_lookup_failed");
      }
    };

    if let Some((token, expires_at)) = existing_token {
      log_access(req, false);
      let response = json!({
        "user_token": token,
        "expires_at": expires_at,
        "payload": user_payload,
      });
      return json_response_value(StatusCode::Ok, response);
    }
  }
  let issued = match manager.issue_token(user_payload.clone()).await {
    Ok(issue) => issue,
    Err(_) => {
      return error_response(StatusCode::InternalServerError, "login_issue_failed");
    }
  };

  log_access(req, false);

  let response = json!({
    "user_token": issued.token,
    "expires_at": issued.expires_at,
    "payload": user_payload,
  });
  json_response_value(StatusCode::Ok, response)
}

pub async fn logout(req: &Request) -> Response {
  with_auth_no_renew(req, |_req, db, _, token| async move {
    let manager = TokenManager::new(db.pool());
    match manager.delete_token(&token).await {
      Ok(_) => json_response_value(StatusCode::Ok, json!({ "status": "logged_out" })),
      Err(_) => error_response(StatusCode::InternalServerError, "logout_failed"),
    }
  })
  .await
}

pub async fn profile(req: &Request) -> Response {
  with_auth(req, true, |_req, _db, validation, _token| async move {
    let payload = validation.record.payload.clone();
    json_response_value(
      StatusCode::Ok,
      json!({
      "payload": payload,
      "renewed": validation.renewed,
      "expires_at": validation.expires_at,
      }),
    )
  })
  .await
}

pub async fn me(req: &Request) -> Response {
  let context = settings_context_from_headers(req);

  with_auth(req, true, |_req, db, validation, _token| async move {
    let payload = validation.record.payload.clone();
    let user_id = match payload.get("user_id").and_then(|value| value.as_i64()) {
      Some(id) => id as i32,
      None => return error_response(StatusCode::Unauthorized, "invalid_token"),
    };

    let businesses = match list_user_businesses(&db, user_id).await {
      Ok(businesses) => businesses,
      Err(response) => return response,
    };
    let active_business_id = match context.business_id.as_ref() {
      Some(identifier) => match resolve_business_id(&db, Some(identifier)).await {
        Ok(id) => Some(id),
        Err(response) => return response,
      },
      None => None,
    };
    let active_business = active_business_id
      .and_then(|id| businesses.iter().find(|business| business.id == id))
      .map(|business| json!(business));
    if active_business_id.is_some() && active_business.is_none() {
      return error_response(StatusCode::Forbidden, "invalid_business_membership");
    }

    let mut response = json!({
      "payload": payload,
      "renewed": validation.renewed,
      "expires_at": validation.expires_at,
      "businesses": businesses,
    });
    if let Some(active_business) = active_business {
      response["active_business"] = active_business;
    }
    if active_business_id.is_some() && context.app_id.is_some() {
      if let Err(response_error) =
        add_settings_to_response(&mut response, &db, user_id, context).await
      {
        return response_error;
      }
    }
    json_response_value(StatusCode::Ok, response)
  })
  .await
}

pub async fn patch_my_settings(req: &Request) -> Response {
  let payload: SettingsPatchPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  if !payload.settings_patch.is_object() {
    return error_response(StatusCode::BadRequest, "invalid_settings_patch");
  }

  with_auth(req, true, |_req, db, validation, _token| async move {
    let user_id = match validation
      .record
      .payload
      .get("user_id")
      .and_then(|value| value.as_i64())
    {
      Some(id) => id as i32,
      None => return error_response(StatusCode::Unauthorized, "invalid_token"),
    };
    let app_id = match normalize_app_id(Some(payload.app_id)) {
      Ok(Some(app_id)) => app_id,
      Ok(None) => return error_response(StatusCode::BadRequest, "missing_app_id"),
      Err(response) => return response,
    };
    let business_id = match resolve_business_id(&db, Some(&payload.business_id)).await {
      Ok(id) => id,
      Err(response) => return response,
    };
    if let Err(response) = ensure_business_user(&db, business_id, user_id).await {
      return response;
    }

    let patch = payload.settings_patch.to_string();
    match sqlx::query("CALL auth.patch_user_app_settings($1, $2, $3, $4::jsonb)")
      .bind(business_id)
      .bind(user_id)
      .bind(&app_id)
      .bind(&patch)
      .execute(db.pool())
      .await
    {
      Ok(_) => {}
      Err(_) => {
        return error_response(StatusCode::InternalServerError, "patch_settings_failed");
      }
    }

    let settings = match load_user_app_settings(
      &db,
      user_id,
      SettingsContextPayload {
        business_id: Some(FlexibleId::Int(business_id)),
        app_id: Some(app_id.clone()),
      },
    )
    .await
    {
      Ok(Some(value)) => value,
      Ok(None) => json!({}),
      Err(response) => return response,
    };
    json_response_value(
      StatusCode::Ok,
      json!({
      "business_id": business_id,
      "user_id": user_id,
      "app_id": app_id,
      "settings": settings,
      }),
    )
  })
  .await
}

pub async fn check_permission(req: &Request) -> Response {
  #[derive(Deserialize, Default)]
  struct CheckPermissionRequest {
    business_id: Option<FlexibleId>,
    service_id: Option<FlexibleId>,
  }

  let request_payload: CheckPermissionRequest = if req.body.trim().is_empty() {
    CheckPermissionRequest::default()
  } else {
    match serde_json::from_slice(req.body.as_bytes()) {
      Ok(payload) => payload,
      Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
    }
  };

  let (db, validation, token) = match require_token_with_renew_no_log(req).await {
    Ok(values) => values,
    Err(response) => return response,
  };

  let service_token = extract_service_token(req);
  let service_id = request_payload
    .service_id
    .as_ref()
    .and_then(|id| id.parse_int());
  if request_payload.service_id.is_some() && service_id.is_none() {
    return error_response(StatusCode::BadRequest, "invalid_service_id");
  }
  if service_token.is_some() == service_id.is_some() {
    return error_response(StatusCode::BadRequest, "invalid_request_body");
  }

  let service_id = if let Some(service_token) = service_token {
    let manager = TokenManager::new(db.pool());
    let service_validation = match manager.validate_service_token(&service_token).await {
      Ok(validation) => validation,
      Err(crate::auth::TokenError::NotFound) => {
        return unauthorized_response("invalid_service_token");
      }
      Err(crate::auth::TokenError::Expired) => return unauthorized_response("expired_token"),
      Err(crate::auth::TokenError::Database(_)) => {
        return error_response(
          StatusCode::InternalServerError,
          "service_token_validation_failed",
        );
      }
    };
    let service_id = match service_validation
      .record
      .payload
      .get("service_id")
      .and_then(|value| value.as_i64())
      .map(|value| value as i32)
    {
      Some(service_id) => service_id,
      None => return unauthorized_response("invalid_service_token"),
    };
    match sqlx::query_scalar::<_, bool>("SELECT status FROM auth.services WHERE id = $1")
      .bind(service_id)
      .fetch_optional(db.pool())
      .await
    {
      Ok(Some(true)) => service_id,
      Ok(Some(false)) => return unauthorized_response("service_inactive"),
      Ok(None) => return unauthorized_response("invalid_service_token"),
      Err(_) => {
        return error_response(StatusCode::InternalServerError, "service_lookup_failed");
      }
    }
  } else {
    let service_id = match service_id {
      Some(id) => id,
      None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
    };
    match sqlx::query_scalar::<_, bool>("SELECT status FROM auth.services WHERE id = $1")
      .bind(service_id)
      .fetch_optional(db.pool())
      .await
    {
      Ok(Some(true)) => service_id,
      Ok(Some(false)) => return unauthorized_response("service_inactive"),
      Ok(None) => return error_response(StatusCode::BadRequest, "invalid_service_id"),
      Err(_) => {
        return error_response(StatusCode::InternalServerError, "service_lookup_failed");
      }
    }
  };

  let payload = validation.record.payload.clone();
  let user_id = match payload
    .get("user_id")
    .and_then(|value| value.as_i64())
    .map(|v| v as i32)
  {
    Some(user_id) => user_id,
    None => return unauthorized_response("invalid_token"),
  };
  let business_id = match resolve_business_id(&db, request_payload.business_id.as_ref()).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64;

  let manager = TokenManager::new(db.pool());
  let cached_access = match manager
    .load_access_cache(&token, business_id, service_id)
    .await
  {
    Ok(Some(cache)) if cache.expires_at > now => Some(cache.access_json),
    Ok(_) => None,
    Err(_) => {
      return error_response(StatusCode::InternalServerError, "load_access_cache_failed");
    }
  };
  let used_cache = cached_access.is_some();

  let access_json = if let Some(access) = cached_access {
    access
  } else {
    let (roles, permissions) =
      match load_roles_and_permissions(&db, user_id, business_id, service_id).await {
        Ok(result) => result,
        Err(response) => return response,
      };
    let expires_at = now + manager.ttl();
    let access = json!({
      "user_id": user_id,
      "business_id": business_id,
      "service_id": service_id,
      "roles": roles,
      "permissions": permissions,
      "scopes": [],
      "expires_at": expires_at,
    });
    if let Err(_) = manager
      .store_access_cache(&token, business_id, service_id, &access, expires_at)
      .await
    {
      return error_response(StatusCode::InternalServerError, "store_access_cache_failed");
    }
    access
  };

  log_access(req, used_cache);

  json_response_value(
    StatusCode::Ok,
    json!({
      "valid": true,
      "access": access_json,
      "renewed": validation.renewed,
      "expires_at": validation.expires_at,
    }),
  )
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

async fn create_user_from_request(req: &Request, public_registration: bool) -> Response {
  let db = if public_registration {
    match get_db_connection().await {
      Ok(db) => db,
      Err(response) => return response,
    }
  } else {
    match require_token_with_renew(req).await {
      Ok((db, _, _)) => db,
      Err(response) => return response,
    }
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
    Ok(user) => {
      if public_registration {
        log_access(req, false);
      }
      json_response(StatusCode::Created, &user)
    }
    Err(_) => error_response(StatusCode::InternalServerError, "create_user_failed"),
  }
}

pub async fn register_user(req: &Request) -> Response {
  create_user_from_request(req, true).await
}

pub async fn create_user(req: &Request) -> Response {
  create_user_from_request(req, false).await
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
    Ok(users) => json_response(StatusCode::Ok, &users),
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
    Ok(Some(user)) => json_response(StatusCode::Ok, &user),
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
    Ok(_) => json_response_value(StatusCode::Ok, json!({ "status": "success" })),
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
      Ok(revoked) => json_response_value(
        StatusCode::Ok,
        json!({
          "status": "user_deleted",
          "user_id": id,
          "revoked_tokens": revoked
        }),
      ),
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
