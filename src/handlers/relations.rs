use httpageboy::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;

use super::roles::Role;
use super::users::User;
use super::{error_response, require_token_without_renew};

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
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
      "assign_role_service_failed",
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
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  match sqlx::query("CALL auth.remove_role_from_service($1, $2)")
    .bind(payload.service_id)
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
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
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
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
    Err(_) => error_response(StatusCode::InternalServerError, "assign_role_person_failed"),
  }
}

pub async fn remove_role_from_person_in_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: PersonServiceRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
  };
  match sqlx::query("CALL auth.remove_role_from_person_in_service($1, $2, $3)")
    .bind(payload.person_id)
    .bind(payload.service_id)
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
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id: i32 = match req.params.get("person_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_person_id"),
  };
  let service_id: i32 = match req.params.get("service_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
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
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let service_id: i32 = match req.params.get("service_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  let role_id: i32 = match req.params.get("role_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_role_id"),
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
  person_id: i32,
  service_id: i32,
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

  let person_id = req
    .params
    .get("person_id")
    .and_then(|value| value.parse::<i32>().ok());
  let service_id = req
    .params
    .get("service_id")
    .and_then(|value| value.parse::<i32>().ok());
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
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload = match parse_check_permission_payload(req) {
    Ok(payload) => payload,
    Err(response) => return response,
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
    Err(_) => error_response(StatusCode::InternalServerError, "check_permission_failed"),
  }
}
