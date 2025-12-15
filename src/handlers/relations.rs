use httpageboy::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;

use super::roles::Role;
use super::users::User;
use super::{
  FlexibleId, error_response, require_token_with_renew, resolve_permission_id, resolve_person_id,
  resolve_service_id,
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
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
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
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "role_removed_from_service" })
        .to_string()
        .into_bytes(),
    },
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
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "list_service_roles_failed"),
  }
}

#[derive(Deserialize)]
pub struct PersonServiceRolePayload {
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
  match sqlx::query("CALL auth.assign_role_to_person_in_service($1, $2, $3)")
    .bind(person_id)
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
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
  match sqlx::query("CALL auth.remove_role_from_person_in_service($1, $2, $3)")
    .bind(person_id)
    .bind(service_id)
    .bind(payload.role_id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "role_removed_from_person" })
        .to_string()
        .into_bytes(),
    },
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
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
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
    Ok(users) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&users).unwrap(),
    },
    Err(_) => error_response(
      StatusCode::InternalServerError,
      "list_persons_with_role_failed",
    ),
  }
}

#[derive(Deserialize)]
pub struct CheckPermissionPayload {
  person_id: FlexibleId,
  service_id: FlexibleId,
  permission_name: String,
}

fn parse_check_permission_payload(req: &Request) -> Result<CheckPermissionPayload, Response> {
  if !req.body.trim().is_empty() {
    match serde_json::from_slice::<CheckPermissionPayload>(req.body.as_bytes()) {
      Ok(payload) => return Ok(payload),
      Err(err) => {
        eprintln!(
          "[parse-error] check_permission body='{}' err={}",
          req.body.replace('\n', "\\n"),
          err
        );
      }
    }
  }

  let person_id = req.params.get("person_id").cloned().map(FlexibleId::from);
  let service_id = req.params.get("service_id").cloned().map(FlexibleId::from);
  let permission_name = req.params.get("permission_name").cloned();

  match (person_id, service_id, permission_name) {
    (Some(person_id), Some(service_id), Some(permission_name)) => Ok(CheckPermissionPayload {
      person_id,
      service_id,
      permission_name,
    }),
    _ => Err(error_response(
      StatusCode::BadRequest,
      "invalid_request_body",
    )),
  }
}

pub async fn check_person_permission_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload = match parse_check_permission_payload(req) {
    Ok(payload) => payload,
    Err(response) => return response,
  };
  let person_id = match resolve_person_id(&db, &payload.person_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  let service_id = match resolve_service_id(&db, &payload.service_id, false).await {
    Ok(id) => id,
    Err(response) => return response,
  };
  match sqlx::query_scalar::<_, bool>(
    "SELECT * FROM auth.check_person_permission_in_service($1, $2, $3)",
  )
  .bind(person_id)
  .bind(service_id)
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
    Err(_) => error_response(StatusCode::InternalServerError, "check_permission_failed"),
  }
}

#[derive(Deserialize)]
pub struct PersonServicePermissionPayload {
  person_id: FlexibleId,
  service_id: FlexibleId,
  permission_id: Option<FlexibleId>,
  permission_name: Option<String>,
}

async fn ensure_direct_role(
  db: &crate::database::DB,
  person_id: i32,
  service_id: i32,
) -> Result<i32, Response> {
  let role_name = format!("direct:{}:{}", person_id, service_id);

  let existing = sqlx::query_scalar::<_, i32>("SELECT id FROM auth.role WHERE name = $1")
    .bind(&role_name)
    .fetch_optional(db.pool())
    .await
    .map_err(|_| {
      error_response(
        StatusCode::InternalServerError,
        "resolve_direct_role_failed",
      )
    })?;
  if let Some(id) = existing {
    return Ok(id);
  }

  let inserted = sqlx::query_scalar::<_, i32>(
    "INSERT INTO auth.role (name) VALUES ($1)
      ON CONFLICT (name) DO NOTHING
      RETURNING id",
  )
  .bind(&role_name)
  .fetch_optional(db.pool())
  .await
  .map_err(|_| error_response(StatusCode::InternalServerError, "create_direct_role_failed"))?;

  if let Some(id) = inserted {
    return Ok(id);
  }

  sqlx::query_scalar::<_, i32>("SELECT id FROM auth.role WHERE name = $1")
    .bind(&role_name)
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

  let permission_identifier = match (payload.permission_id, payload.permission_name) {
    (Some(id), _) => id,
    (None, Some(name)) => FlexibleId::from(name),
    _ => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };

  let permission_id = match resolve_permission_id(&db, &permission_identifier).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  let role_id = match ensure_direct_role(&db, person_id, service_id).await {
    Ok(id) => id,
    Err(response) => return response,
  };

  if let Err(_) = sqlx::query(
    "INSERT INTO auth.service_roles (service_id, role_id) VALUES ($1, $2)
      ON CONFLICT (service_id, role_id) DO NOTHING",
  )
  .bind(service_id)
  .bind(role_id)
  .execute(db.pool())
  .await
  {
    return error_response(StatusCode::InternalServerError, "link_role_service_failed");
  }

  if let Err(_) = sqlx::query(
    "INSERT INTO auth.role_permission (role_id, permission_id) VALUES ($1, $2)
      ON CONFLICT (role_id, permission_id) DO NOTHING",
  )
  .bind(role_id)
  .bind(permission_id)
  .execute(db.pool())
  .await
  {
    return error_response(StatusCode::InternalServerError, "assign_permission_failed");
  }

  if let Err(_) = sqlx::query(
    "INSERT INTO auth.person_service_role (person_id, service_id, role_id) VALUES ($1, $2, $3)
      ON CONFLICT (person_id, service_id, role_id) DO NOTHING",
  )
  .bind(person_id)
  .bind(service_id)
  .bind(role_id)
  .execute(db.pool())
  .await
  {
    return error_response(StatusCode::InternalServerError, "assign_role_person_failed");
  }

  Response {
    status: StatusCode::Ok.to_string(),
    content_type: "application/json".to_string(),
    content: json!({
      "status": "permission_granted",
      "person_id": person_id,
      "service_id": service_id,
      "permission_id": permission_id,
      "role_id": role_id
    })
    .to_string()
    .into_bytes(),
  }
}
