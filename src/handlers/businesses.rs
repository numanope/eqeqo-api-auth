use crate::responses::{json_response, json_response_value};
use httpageboy::{Request, Response, StatusCode};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
  FlexibleId, error_response, require_token_with_renew, resolve_business_id, resolve_person_id,
};

#[derive(Serialize, sqlx::FromRow)]
pub struct Business {
  id: i32,
  name: String,
  legal_name: Option<String>,
  document_type: Option<String>,
  document_number: Option<String>,
  status: bool,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct BusinessUser {
  business_id: i32,
  person_id: i32,
  username: String,
  name: String,
  status: bool,
}

#[derive(Deserialize)]
pub struct BusinessPayload {
  name: String,
  legal_name: Option<String>,
  document_type: Option<String>,
  document_number: Option<String>,
  status: Option<bool>,
  service_id: Option<FlexibleId>,
}

#[derive(Deserialize)]
pub struct BusinessUserPayload {
  business_id: FlexibleId,
  person_id: FlexibleId,
}

#[derive(Deserialize)]
pub struct BusinessInvitationPayload {
  business_id: FlexibleId,
  service_id: FlexibleId,
  role_id: i32,
  expires_in_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub struct AcceptBusinessInvitationPayload {
  code: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct BusinessInvitation {
  id: i32,
  code: String,
  business_id: i32,
  service_id: i32,
  role_id: i32,
  expires_at: i64,
}

fn normalize_optional(value: Option<String>) -> Option<String> {
  value
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty())
}

fn normalize_document_type(value: Option<String>) -> Result<Option<String>, Response> {
  let Some(value) = normalize_optional(value) else {
    return Ok(None);
  };
  let normalized = value.to_uppercase();
  match normalized.as_str() {
    "DNI" | "CE" | "RUC" => Ok(Some(normalized)),
    _ => Err(error_response(
      StatusCode::BadRequest,
      "invalid_document_type",
    )),
  }
}

fn current_epoch() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64
}

fn generate_invitation_code() -> String {
  let mut bytes = [0u8; 12];
  OsRng.fill_bytes(&mut bytes);
  bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn token_person_id(validation: &crate::auth::TokenValidation) -> Result<i32, Response> {
  validation
    .record
    .payload
    .get("user_id")
    .and_then(|value| value.as_i64())
    .map(|id| id as i32)
    .ok_or_else(|| error_response(StatusCode::Unauthorized, "invalid_token"))
}

async fn require_business_admin(req: &Request) -> Result<crate::database::DB, Response> {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return Err(response),
  };
  let user_id = token_person_id(&validation)?;

  match sqlx::query_scalar::<_, Option<bool>>("SELECT auth.sp_person_can_register_services($1)")
    .bind(user_id)
    .fetch_one(db.pool())
    .await
  {
    Ok(Some(true)) => Ok(db),
    Ok(Some(false)) => Err(error_response(
      StatusCode::Forbidden,
      "insufficient_permissions",
    )),
    Ok(None) => Err(error_response(StatusCode::Unauthorized, "invalid_token")),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "business_permission_check_failed",
    )),
  }
}

async fn require_business_role_admin(
  db: &crate::database::DB,
  person_id: i32,
  business_id: i32,
) -> Result<(), Response> {
  match sqlx::query_scalar::<_, bool>("SELECT auth.sp_business_role_admin_exists($1, $2)")
    .bind(person_id)
    .bind(business_id)
    .fetch_one(db.pool())
    .await
  {
    Ok(true) => Ok(()),
    Ok(false) => Err(error_response(
      StatusCode::Forbidden,
      "insufficient_business_permissions",
    )),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "business_permission_check_failed",
    )),
  }
}

async fn require_global_or_business_admin(
  req: &Request,
  business_id: i32,
) -> Result<crate::database::DB, Response> {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return Err(response),
  };
  let user_id = token_person_id(&validation)?;

  match sqlx::query_scalar::<_, Option<bool>>("SELECT auth.sp_person_can_register_services($1)")
    .bind(user_id)
    .fetch_one(db.pool())
    .await
  {
    Ok(Some(true)) => Ok(db),
    Ok(Some(false)) => {
      require_business_role_admin(&db, user_id, business_id).await?;
      Ok(db)
    }
    Ok(None) => Err(error_response(StatusCode::Unauthorized, "invalid_token")),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "business_permission_check_failed",
    )),
  }
}

pub async fn list_businesses(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };

  match sqlx::query_as::<_, Business>("SELECT * FROM auth.sp_list_businesses()")
    .fetch_all(db.pool())
    .await
  {
    Ok(businesses) => json_response(StatusCode::Ok, &businesses),
    Err(_) => error_response(StatusCode::InternalServerError, "list_businesses_failed"),
  }
}

pub async fn list_my_businesses(req: &Request) -> Response {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let user_id = match validation
    .record
    .payload
    .get("user_id")
    .and_then(|value| value.as_i64())
  {
    Some(id) => id as i32,
    None => return error_response(StatusCode::Unauthorized, "invalid_token"),
  };

  match sqlx::query_as::<_, Business>("SELECT * FROM auth.sp_list_user_businesses($1)")
    .bind(user_id)
    .fetch_all(db.pool())
    .await
  {
    Ok(businesses) => json_response(StatusCode::Ok, &businesses),
    Err(_) => error_response(StatusCode::InternalServerError, "list_my_businesses_failed"),
  }
}

pub async fn create_business(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let payload: BusinessPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let name = payload.name.trim();
  if name.is_empty() {
    return error_response(StatusCode::BadRequest, "invalid_business_name");
  }
  let document_type = match normalize_document_type(payload.document_type) {
    Ok(value) => value,
    Err(response) => return response,
  };

  match sqlx::query_as::<_, Business>("SELECT * FROM auth.sp_create_business($1, $2, $3, $4, $5)")
    .bind(name)
    .bind(normalize_optional(payload.legal_name))
    .bind(document_type)
    .bind(normalize_optional(payload.document_number))
    .bind(payload.status)
    .fetch_one(db.pool())
    .await
  {
    Ok(business) => json_response(StatusCode::Created, &business),
    Err(_) => error_response(StatusCode::InternalServerError, "create_business_failed"),
  }
}

pub async fn create_my_business(req: &Request) -> Response {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id = match token_person_id(&validation) {
    Ok(id) => id,
    Err(response) => return response,
  };
  let payload: BusinessPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let name = payload.name.trim();
  if name.is_empty() {
    return error_response(StatusCode::BadRequest, "invalid_business_name");
  }
  let document_type = match normalize_document_type(payload.document_type) {
    Ok(value) => value,
    Err(response) => return response,
  };
  let service_id = match payload.service_id {
    Some(service_id) => match super::resolve_service_id(&db, &service_id, false).await {
      Ok(id) => id,
      Err(response) => return response,
    },
    None => match sqlx::query_scalar::<_, Option<i32>>("SELECT auth.sp_default_store_service()")
      .fetch_one(db.pool())
      .await
    {
      Ok(Some(id)) => id,
      Ok(None) => {
        return error_response(StatusCode::InternalServerError, "default_service_missing");
      }
      Err(_) => return error_response(StatusCode::InternalServerError, "load_service_failed"),
    },
  };
  let role_id = match sqlx::query_scalar::<_, Option<i32>>("SELECT auth.sp_admin_role_id()")
    .fetch_one(db.pool())
    .await
  {
    Ok(Some(id)) => id,
    Ok(None) => return error_response(StatusCode::InternalServerError, "admin_role_missing"),
    Err(_) => return error_response(StatusCode::InternalServerError, "load_role_failed"),
  };
  let business = match sqlx::query_as::<_, Business>(
    "SELECT * FROM auth.sp_create_my_business($1, $2, $3, $4, $5, $6, $7)",
  )
  .bind(person_id)
  .bind(name)
  .bind(normalize_optional(payload.legal_name))
  .bind(document_type)
  .bind(normalize_optional(payload.document_number))
  .bind(service_id)
  .bind(role_id)
  .fetch_one(db.pool())
  .await
  {
    Ok(business) => business,
    Err(_) => return error_response(StatusCode::InternalServerError, "create_business_failed"),
  };
  let business_id = business.id;

  json_response_value(
    StatusCode::Created,
    json!({
      "business": business,
      "business_id": business_id,
      "service_id": service_id,
      "role_id": role_id,
      "status": "business_created",
    }),
  )
}

pub async fn update_business(req: &Request) -> Response {
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_business_id"),
  };
  let db = match require_global_or_business_admin(req, id).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let payload: BusinessPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let name = payload.name.trim();
  if name.is_empty() {
    return error_response(StatusCode::BadRequest, "invalid_business_name");
  }
  let document_type = match normalize_document_type(payload.document_type) {
    Ok(value) => value,
    Err(response) => return response,
  };

  match sqlx::query_as::<_, Business>(
    "SELECT * FROM auth.sp_update_business($1, $2, $3, $4, $5, $6)",
  )
  .bind(id)
  .bind(name)
  .bind(normalize_optional(payload.legal_name))
  .bind(document_type)
  .bind(normalize_optional(payload.document_number))
  .bind(payload.status)
  .fetch_optional(db.pool())
  .await
  {
    Ok(Some(business)) => json_response(StatusCode::Ok, &business),
    Ok(None) => error_response(StatusCode::NotFound, "business_not_found"),
    Err(_) => error_response(StatusCode::InternalServerError, "update_business_failed"),
  }
}

pub async fn delete_business(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_business_id"),
  };

  match sqlx::query_scalar::<_, i64>("SELECT auth.sp_delete_business($1)")
    .bind(id)
    .fetch_one(db.pool())
    .await
  {
    Ok(rows) if rows > 0 => json_response_value(
      StatusCode::Ok,
      json!({ "status": "business_deleted", "business_id": id }),
    ),
    Ok(_) => error_response(StatusCode::NotFound, "business_not_found"),
    Err(_) => error_response(StatusCode::InternalServerError, "delete_business_failed"),
  }
}

pub async fn list_business_users(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let id = match req
    .params
    .get("id")
    .map(|value| FlexibleId::from(value.as_str()))
  {
    Some(identifier) => match resolve_business_id(&db, Some(&identifier)).await {
      Ok(id) => id,
      Err(response) => return response,
    },
    None => return error_response(StatusCode::BadRequest, "invalid_business_id"),
  };

  match sqlx::query_as::<_, BusinessUser>("SELECT * FROM auth.sp_list_business_users($1)")
    .bind(id)
    .fetch_all(db.pool())
    .await
  {
    Ok(users) => json_response(StatusCode::Ok, &users),
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "list_business_users_failed",
    ),
  }
}

pub async fn assign_user_to_business(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let payload: BusinessUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let business_id = match resolve_business_id(&db, Some(&payload.business_id)).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  match sqlx::query("CALL auth.sp_assign_business_user($1, $2)")
    .bind(business_id)
    .bind(person_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => json_response_value(
      StatusCode::Ok,
      json!({
        "status": "business_user_assigned",
        "business_id": business_id,
        "person_id": person_id,
      }),
    ),
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "assign_business_user_failed",
    ),
  }
}

pub async fn remove_user_from_business(req: &Request) -> Response {
  let db = match require_business_admin(req).await {
    Ok(db) => db,
    Err(response) => return response,
  };
  let payload: BusinessUserPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let business_id = match resolve_business_id(&db, Some(&payload.business_id)).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  match sqlx::query_scalar::<_, i64>("SELECT auth.sp_remove_business_user($1, $2)")
    .bind(business_id)
    .bind(person_id)
    .fetch_one(db.pool())
    .await
  {
    Ok(rows) if rows > 0 => json_response_value(
      StatusCode::Ok,
      json!({
        "status": "business_user_removed",
        "business_id": business_id,
        "person_id": person_id,
      }),
    ),
    Ok(_) => error_response(StatusCode::NotFound, "business_user_not_found"),
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "remove_business_user_failed",
    ),
  }
}

pub async fn create_business_invitation(req: &Request) -> Response {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id = match validation
    .record
    .payload
    .get("user_id")
    .and_then(|value| value.as_i64())
  {
    Some(id) => id as i32,
    None => return error_response(StatusCode::Unauthorized, "invalid_token"),
  };
  let payload: BusinessInvitationPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let business_id = match resolve_business_id(&db, Some(&payload.business_id)).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  if let Err(response) = require_business_role_admin(&db, person_id, business_id).await {
    return response;
  }
  let service_id = match super::resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let expires_at = current_epoch() + payload.expires_in_seconds.unwrap_or(86_400);
  let code = generate_invitation_code();

  match sqlx::query_as::<_, BusinessInvitation>(
    "SELECT * FROM auth.sp_create_business_invitation($1, $2, $3, $4, $5, $6)",
  )
  .bind(code)
  .bind(business_id)
  .bind(service_id)
  .bind(payload.role_id)
  .bind(person_id)
  .bind(expires_at)
  .fetch_one(db.pool())
  .await
  {
    Ok(invitation) => json_response(StatusCode::Created, &invitation),
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "create_business_invitation_failed",
    ),
  }
}

pub async fn accept_business_invitation(req: &Request) -> Response {
  let (db, validation, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id = match validation
    .record
    .payload
    .get("user_id")
    .and_then(|value| value.as_i64())
  {
    Some(id) => id as i32,
    None => return error_response(StatusCode::Unauthorized, "invalid_token"),
  };
  let payload: AcceptBusinessInvitationPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(payload) => payload,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let code = payload.code.trim();
  if code.is_empty() {
    return error_response(StatusCode::BadRequest, "invalid_invitation_code");
  }

  let invitation = match sqlx::query_as::<_, (i32, i32, i32)>(
    "SELECT * FROM auth.sp_accept_business_invitation($1, $2, $3)",
  )
  .bind(code)
  .bind(person_id)
  .bind(current_epoch())
  .fetch_optional(db.pool())
  .await
  {
    Ok(Some(invitation)) => invitation,
    Ok(None) => return error_response(StatusCode::BadRequest, "invalid_invitation_code"),
    Err(_) => {
      return error_response(
        StatusCode::InternalServerError,
        "load_business_invitation_failed",
      );
    }
  };

  json_response_value(
    StatusCode::Ok,
    json!({
      "status": "business_invitation_accepted",
      "business_id": invitation.0,
      "service_id": invitation.1,
      "role_id": invitation.2,
    }),
  )
}
