use crate::database::DB;
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{error_response, require_token_without_renew};

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
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
    Err(err) => {
      eprintln!("[handler-error] create_permission: {}", err);
      error_response(
        StatusCode::InternalServerError,
        "create_permission_failed",
      )
    }
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
      "list_permissions_failed",
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
    None => return error_response(StatusCode::BadRequest, "invalid_permission_id"),
  };
  let payload: UpdatePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
        "update_permission_failed",
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
    None => return error_response(StatusCode::BadRequest, "invalid_permission_id"),
  };
  match sqlx::query("CALL auth.delete_permission($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "permission_deleted", "permission_id": id })
        .to_string()
        .into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "delete_permission_failed",
    ),
  }
}

#[derive(Deserialize)]
pub struct RolePermissionPayload {
  service_id: i32,
  role_id: i32,
  permission_id: i32,
}

async fn ensure_service_role_exists(
  db: &DB,
  service_id: i32,
  role_id: i32,
) -> Result<(), Response> {
  match sqlx::query_scalar::<_, bool>(
    "SELECT EXISTS (
      SELECT 1
      FROM auth.service_roles
      WHERE service_id = $1 AND role_id = $2
    )",
  )
    .bind(service_id)
    .bind(role_id)
    .fetch_one(db.pool())
    .await
  {
    Ok(true) => Ok(()),
    Ok(false) => Err(error_response(
      StatusCode::BadRequest,
      "role_not_in_service",
    )),
    Err(_) => Err(error_response(
      StatusCode::InternalServerError,
      "service_role_check_failed",
    )),
  }
}

pub async fn assign_permission_to_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: RolePermissionPayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  if let Err(response) = ensure_service_role_exists(&db, payload.service_id, payload.role_id).await
  {
    return response;
  }
  match sqlx::query("CALL auth.assign_permission_to_role($1, $2, $3)")
    .bind(payload.service_id)
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
      "assign_permission_failed",
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
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  match sqlx::query("CALL auth.remove_permission_from_role($1, $2, $3)")
    .bind(payload.service_id)
    .bind(payload.role_id)
    .bind(payload.permission_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({
        "status": "permission_removed_from_role",
        "service_id": payload.service_id,
        "role_id": payload.role_id,
        "permission_id": payload.permission_id
      })
      .to_string()
      .into_bytes(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "remove_permission_failed",
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
    None => return error_response(StatusCode::BadRequest, "invalid_role_id"),
  };
  let service_id: i32 = match req.params.get("service_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  match sqlx::query_as::<_, Permission>("SELECT * FROM auth.list_role_permissions($1, $2)")
    .bind(id)
    .bind(service_id)
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
      "list_role_permissions_failed",
    ),
  }
}
