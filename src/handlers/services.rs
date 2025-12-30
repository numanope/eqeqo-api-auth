use crate::auth::TokenManager;
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{error_response, require_token_with_renew};

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
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateServicePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
    Err(_) => error_response(StatusCode::InternalServerError, "create_service_failed"),
  }
}

pub async fn list_services(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
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
    Err(_) => error_response(StatusCode::InternalServerError, "list_services_failed"),
  }
}

#[derive(Deserialize)]
pub struct UpdateServicePayload {
  name: Option<String>,
  description: Option<String>,
}

pub async fn update_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  let payload: UpdateServicePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "invalid_request_body"),
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
    Err(_) => error_response(StatusCode::InternalServerError, "update_service_failed"),
  }
}

pub async fn delete_service(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };
  match sqlx::query("CALL auth.delete_service($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "service_deleted", "service_id": id })
        .to_string()
        .into_bytes(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "delete_service_failed"),
  }
}

#[derive(sqlx::FromRow)]
struct ServiceTokenData {
  id: i32,
  name: String,
  status: bool,
}

pub async fn issue_service_token(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_service_id"),
  };

  let service = match sqlx::query_as::<_, ServiceTokenData>(
    "SELECT id, name, status FROM auth.services WHERE id = $1",
  )
  .bind(id)
  .fetch_optional(db.pool())
  .await
  {
    Ok(Some(service)) => service,
    Ok(None) => return error_response(StatusCode::NotFound, "service_not_found"),
    Err(_) => return error_response(StatusCode::InternalServerError, "load_service_failed"),
  };

  if !service.status {
    return error_response(StatusCode::Forbidden, "service_inactive");
  }

  let manager = TokenManager::new(db.pool());
  let issued = match manager.issue_service_token(service.id, &service.name).await {
    Ok(issue) => issue,
    Err(_) => {
      return error_response(
        StatusCode::InternalServerError,
        "issue_service_token_failed",
      );
    }
  };

  Response {
    status: StatusCode::Ok.to_string(),
    content_type: "application/json".to_string(),
    content: json!({
      "service_id": service.id,
      "service_name": service.name,
      "service_token": issued.token,
      "expires_at": issued.expires_at,
    })
    .to_string()
    .into_bytes(),
  }
}

pub async fn list_services_of_person(req: &Request) -> Response {
  let (db, _, _) = match require_token_with_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let person_id: i32 = match req.params.get("person_id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "invalid_person_id"),
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
      "list_person_services_failed",
    ),
  }
}
