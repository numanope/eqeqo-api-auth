use crate::auth::TokenManager;
use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
  error_response, get_db_connection, log_access, require_token_without_renew,
  unauthorized_response, with_auth, with_auth_no_renew,
};

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
