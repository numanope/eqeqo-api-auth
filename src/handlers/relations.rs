use crate::auth::TokenManager;
use crate::responses::{json_response, json_response_value};
use httpageboy::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use super::roles::Role;
use super::users::User;
use super::{
  FlexibleId, default_business_id, error_response, load_roles_and_permissions, log_access,
  require_token_with_renew, require_token_with_renew_no_log, resolve_business_id,
  resolve_permission_id, resolve_person_id, resolve_service_id,
};

#[derive(Deserialize)]
pub struct ServiceRolePayload {
  service_id: FlexibleId,
  role_id: i32,
}

pub async fn assign_role_to_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: ServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let service_id = match resolve_service_id(&db, &payload.service_id, true).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query("CALL auth.assign_role_to_service($1, $2)")
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => {
      let manager = TokenManager::new(db.pool());
      if let Err(_) = manager.delete_access_cache_for_service(service_id).await {
        return error_response(
          StatusCode::InternalServerError,
          "invalidate_access_cache_failed",
        );
      }
      json_response_value(StatusCode::Ok, json!({ "status": "success" }))
    }
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "assign_role_service_failed",
    ),
  }
}

pub async fn remove_role_from_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: ServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let service_id = match resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query("CALL auth.remove_role_from_service($1, $2)")
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => {
      let manager = TokenManager::new(db.pool());
      if let Err(_) = manager.delete_access_cache_for_service(service_id).await {
        return error_response(
          StatusCode::InternalServerError,
          "invalidate_access_cache_failed",
        );
      }
      json_response_value(
        StatusCode::Ok,
        json!({ "status": "role_removed_from_service" }),
      )
    }
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "remove_role_service_failed",
    ),
  }
}

pub async fn list_service_roles(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let identifier = match req.params.get("id") {
    Some(id) => FlexibleId::from(id.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  let id = match resolve_service_id(&db, &identifier, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_service_roles($1)")
    .bind(id)
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => json_response(StatusCode::Ok, &roles),
    Err(_) => error_response(StatusCode::InternalServerError, "list_service_roles_failed"),
  }
}

#[derive(Deserialize)]
pub struct PersonServiceRolePayload {
  business_id: Option<FlexibleId>,
  person_id: FlexibleId,
  service_id: FlexibleId,
  role_id: i32,
}

pub async fn assign_role_to_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: PersonServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let service_id = match resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let business_id = match resolve_business_id(&db, payload.business_id.as_ref()).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query("CALL auth.assign_role_to_person_in_business_service($1, $2, $3, $4)")
    .bind(person_id)
    .bind(business_id)
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => {
      let manager = TokenManager::new(db.pool());
      if let Err(_) = manager
        .delete_access_cache(person_id, business_id, service_id)
        .await
      {
        return error_response(
          StatusCode::InternalServerError,
          "invalidate_access_cache_failed",
        );
      }
      json_response_value(StatusCode::Ok, json!({ "status": "success" }))
    }
    Err(_) => error_response(StatusCode::InternalServerError, "assign_role_person_failed"),
  }
}

pub async fn remove_role_from_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: PersonServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let service_id = match resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let business_id = match resolve_business_id(&db, payload.business_id.as_ref()).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query("CALL auth.remove_role_from_person_in_business_service($1, $2, $3, $4)")
    .bind(person_id)
    .bind(business_id)
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => {
      let manager = TokenManager::new(db.pool());
      if let Err(_) = manager
        .delete_access_cache(person_id, business_id, service_id)
        .await
      {
        return error_response(
          StatusCode::InternalServerError,
          "invalidate_access_cache_failed",
        );
      }
      json_response_value(
        StatusCode::Ok,
        json!({ "status": "role_removed_from_person" }),
      )
    }
    Err(_) => error_response(StatusCode::InternalServerError, "remove_role_person_failed"),
  }
}

pub async fn list_person_roles_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_identifier = match req.params.get("person_id") {
    Some(value) => FlexibleId::from(value.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_person_id"),
  };
  let service_identifier = match req.params.get("service_id") {
    Some(value) => FlexibleId::from(value.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  let person_id = match resolve_person_id(&db, &person_identifier).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let service_id = match resolve_service_id(&db, &service_identifier, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_person_roles_in_service($1, $2)")
    .bind(person_id)
    .bind(service_id)
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => json_response(StatusCode::Ok, &roles),
    Err(_) => error_response(StatusCode::InternalServerError, "list_person_roles_failed"),
  }
}

pub async fn list_persons_with_role_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let service_identifier = match req.params.get("service_id") {
    Some(value) => FlexibleId::from(value.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  let role_id: i32 = match req.params.get("role_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_role_id"),
  };
  let service_id = match resolve_service_id(&db, &service_identifier, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, User>(
    "SELECT id, username, name FROM auth.list_persons_with_role_in_service($1, $2)",
  )
  .bind(service_id)
  .bind(role_id)
  .fetch_all(db.pool())
  .await
  {
    Ok(users) => json_response(StatusCode::Ok, &users),
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "list_persons_with_role_failed",
    ),
  }
}

#[derive(Deserialize)]
pub struct PersonServicePermissionPayload {
  business_id: Option<FlexibleId>,
  person_id: FlexibleId,
  service_id: FlexibleId,
  permission_id: Option<FlexibleId>,
  permission_name: Option<String>,
}

async fn ensure_direct_role(
  db: &crate::database::DB,
  business_id: i32,
  person_id: i32,
  service_id: i32,
) -> Result<i32, Response> {
  sqlx::query_scalar::<_, i32>("SELECT auth.sp_direct_role_resolve($1, $2, $3)")
    .bind(business_id)
    .bind(person_id)
    .bind(service_id)
    .fetch_one(db.pool())
    .await
    .map_err(|_| {
      error_response(
        StatusCode::InternalServerError,
        "resolve_direct_role_failed",
      )
    })
}

pub async fn grant_permission_to_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };

  let payload: PersonServicePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let service_id = match resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let business_id = match resolve_business_id(&db, payload.business_id.as_ref()).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let permission_identifier = match (payload.permission_id, payload.permission_name) {
    (Some(id), _) => id,
    (None, Some(name)) => FlexibleId::from(name),
    _ => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let permission_id = match resolve_permission_id(&db, &permission_identifier).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let role_id = match ensure_direct_role(&db, business_id, person_id, service_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  if let Err(_) = sqlx::query("CALL auth.sp_grant_person_permission($1, $2, $3, $4, $5)")
    .bind(business_id)
    .bind(person_id)
    .bind(service_id)
    .bind(role_id)
    .bind(permission_id)
    .execute(db.pool())
    .await
  {
    return error_response(StatusCode::InternalServerError, "assign_permission_failed");
  }

  let manager = TokenManager::new(db.pool());
  if let Err(_) = manager
    .delete_access_cache(person_id, business_id, service_id)
    .await
  {
    return error_response(
      StatusCode::InternalServerError,
      "invalidate_access_cache_failed",
    );
  }

  json_response_value(
    StatusCode::Ok,
    json!({
      "status": "permission_granted",
      "business_id": business_id,
      "person_id": person_id,
      "service_id": service_id,
      "permission_id": permission_id,
      "role_id": role_id
    }),
  )
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct PersonData {
  id: i32,
  username: String,
  name: String,
}

pub async fn get_person_service_info(req: &Request) -> Response {
  let (db, validation, token) = match require_token_with_renew_no_log(req).await {
    Ok(result) => result,
    Err(response) => return response,
  };

  let person_identifier = match req.params.get("person_id") {
    Some(value) => FlexibleId::from(value.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_person_id"),
  };

  let service_identifier = match req.params.get("service_id") {
    Some(value) => FlexibleId::from(value.clone()),
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };

  let person_id = match resolve_person_id(&db, &person_identifier).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  if let Some(token_user_id) = validation
    .record
    .payload
    .get("user_id")
    .and_then(|v| v.as_i64())
  {
    if token_user_id as i32 != person_id {
      return error_response(StatusCode::Forbidden, "forbidden_person_lookup");
    }
  }

  let service_id = match resolve_service_id(&db, &service_identifier, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let business_id = match default_business_id(&db).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let person = match sqlx::query_as::<_, PersonData>("SELECT * FROM auth.sp_get_person_data($1)")
    .bind(person_id)
    .fetch_optional(db.pool())
    .await
  {
    Ok(Some(person)) => person,
    Ok(None) => return error_response(StatusCode::NotFound, "person_not_found"),
    Err(_) => return error_response(StatusCode::InternalServerError, "load_person_failed"),
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

  let (roles, permissions) = if let Some(access) = cached_access {
    let roles = access.get("roles").cloned().unwrap_or_else(|| json!([]));
    let permissions = access
      .get("permissions")
      .cloned()
      .unwrap_or_else(|| json!([]));
    (roles, permissions)
  } else {
    let (roles, permissions) =
      match load_roles_and_permissions(&db, person_id, business_id, service_id).await {
        Ok(result) => result,
        Err(response) => return response,
      };
    let expires_at = now + manager.ttl();
    let access = json!({
      "user_id": person_id,
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
    (json!(roles), json!(permissions))
  };

  log_access(req, used_cache);

  json_response_value(
    StatusCode::Ok,
    json!({
      "user": person,
      "business_id": business_id,
      "service_id": service_id,
      "roles": roles,
      "permissions": permissions,
    }),
  )
}
