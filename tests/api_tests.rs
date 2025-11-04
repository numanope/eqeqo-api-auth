use auth_api::auth_server;
use httpageboy::Server;
use httpageboy::test_utils::{SERVER_URL, run_test, setup_test_server};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_server() -> Server {
  let _ = dotenvy::dotenv();
  auth_server(SERVER_URL, 10).await
}

async fn ensure_test_server() {
  setup_test_server(create_test_server).await;
  sleep(Duration::from_millis(100)).await;
}

async fn execute(request: &[u8], expected: &[u8]) -> String {
  ensure_test_server().await;
  run_test(request, expected)
}

fn response_body(resp: &str) -> Option<&str> {
  resp.split("\r\n\r\n").nth(1).map(|body| body.trim())
}

fn parse_json(resp: &str) -> Option<Value> {
  let body = response_body(resp)?;
  serde_json::from_str(body).ok()
}

fn status_line(resp: &str) -> Option<&str> {
  resp.lines().next()
}

fn next_id() -> u64 {
  static COUNTER: AtomicU64 = AtomicU64::new(1_000);
  COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn unique_value(prefix: &str) -> String {
  format!("{}_{}", prefix, next_id())
}

fn unique_number() -> String {
  next_id().to_string()
}

fn request_with_token(method: &str, path: &str, token: &str, body: Option<&str>) -> String {
  let mut request = format!("{method} {path} HTTP/1.1\r\ntoken: {token}\r\n");
  if body.is_some() {
    request.push_str("Content-Type: application/json\r\n");
  }
  request.push_str("\r\n");
  if let Some(body) = body {
    request.push_str(body);
  }
  request
}

async fn create_user_for_tests(token: &str) -> (i32, String) {
  let username = unique_value("user");
  let document_number = unique_number();
  let body = json!({
    "username": username.clone(),
    "password_hash": "test-password",
    "name": "Test User",
    "person_type": "N",
    "document_type": "DNI",
    "document_number": document_number,
  })
  .to_string();
  let request = request_with_token("POST", "/users", token, Some(&body));
  let response = execute(request.as_bytes(), b"\"id\"").await;
  let json = parse_json(&response).expect("json body");
  let id = json["id"].as_i64().expect("id") as i32;
  let returned_username = json["username"].as_str().unwrap_or_default().to_string();
  (id, returned_username)
}

async fn create_service_for_tests(token: &str) -> (i32, String) {
  let name = unique_value("service");
  let body = json!({
    "name": name.clone(),
    "description": "Generated service for tests",
  })
  .to_string();
  let request = request_with_token("POST", "/services", token, Some(&body));
  let response = execute(request.as_bytes(), b"\"id\"").await;
  let json = parse_json(&response).expect("json body");
  let id = json["id"].as_i64().expect("id") as i32;
  let returned_name = json["name"].as_str().unwrap_or_default().to_string();
  (id, returned_name)
}

async fn create_role_for_tests(token: &str) -> (i32, String) {
  let name = unique_value("role");
  let body = json!({ "name": name.clone() }).to_string();
  let request = request_with_token("POST", "/roles", token, Some(&body));
  let response = execute(request.as_bytes(), b"\"id\"").await;
  let json = parse_json(&response).expect("json body");
  let id = json["id"].as_i64().expect("id") as i32;
  let returned_name = json["name"].as_str().unwrap_or_default().to_string();
  (id, returned_name)
}

async fn create_permission_for_tests(token: &str) -> (i32, String) {
  let name = unique_value("permission");
  let body = json!({ "name": name.clone() }).to_string();
  let request = request_with_token("POST", "/permissions", token, Some(&body));
  let response = execute(request.as_bytes(), b"\"id\"").await;
  let json = parse_json(&response).expect("json body");
  let id = json["id"].as_i64().expect("id") as i32;
  let returned_name = json["name"].as_str().unwrap_or_default().to_string();
  (id, returned_name)
}

fn extract_token(resp: &str) -> Option<String> {
  parse_json(resp).and_then(|json| {
    json
      .get("token")
      .and_then(|value| value.as_str().map(|s| s.to_string()))
  })
}

async fn login_and_get_token() -> String {
  let response = execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  )
  .await;
  extract_token(&response).expect("token in login response")
}

#[tokio::test]
async fn home_endpoint_returns_html() {
  execute(b"GET / HTTP/1.1\r\n\r\n", b"Welcome to the Auth API").await;
}

#[tokio::test]
async fn login_succeeds_with_valid_credentials() {
  let response = execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  )
  .await;
  let json = parse_json(&response).expect("json body");
  assert!(json.get("token").is_some(), "token missing in response");
  assert_eq!(json["payload"]["username"], "adm1");
}

#[tokio::test]
async fn login_fails_with_wrong_password() {
  execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"wrong\"}",
    b"Invalid credentials",
  )
  .await;
}

#[tokio::test]
async fn login_fails_with_invalid_body() {
  execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\ntest",
    b"Invalid request body",
  )
  .await;
}

#[tokio::test]
async fn list_users_requires_token() {
  execute(b"GET /users HTTP/1.1\r\n\r\n", b"Missing token header").await;
}

#[tokio::test]
async fn profile_requires_token_header() {
  execute(
    b"GET /auth/profile HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn profile_returns_payload_when_token_valid() {
  let token = login_and_get_token().await;
  let request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let response = execute(request.as_bytes(), b"\"payload\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["payload"]["username"], "adm1");
  assert!(json.get("expires_at").is_some());
}

#[tokio::test]
async fn profile_rejects_invalid_token() {
  execute(
    b"GET /auth/profile HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  )
  .await;
}

#[tokio::test]
async fn check_token_confirms_valid_token() {
  let token = login_and_get_token().await;
  let request = format!("POST /check-token HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let response = execute(request.as_bytes(), b"\"valid\":true").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["payload"]["username"], "adm1");
}

#[tokio::test]
async fn check_token_requires_header() {
  execute(
    b"POST /check-token HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn check_token_rejects_invalid_token() {
  execute(
    b"POST /check-token HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  )
  .await;
}

#[tokio::test]
async fn logout_requires_token_header() {
  execute(
    b"POST /auth/logout HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn logout_revokes_token() {
  let token = login_and_get_token().await;
  let request = format!("POST /auth/logout HTTP/1.1\r\ntoken: {}\r\n\r\n", &token);
  execute(request.as_bytes(), b"logged_out").await;

  let profile_request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", &token);
  execute(profile_request.as_bytes(), b"Invalid token").await;
}

#[tokio::test]
async fn logout_rejects_unknown_token() {
  execute(
    b"POST /auth/logout HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  )
  .await;
}

#[tokio::test]
async fn list_users_returns_seeded_admin() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/users", &token, None);
  let response = execute(request.as_bytes(), b"\"username\":\"adm1\"").await;
  let json = parse_json(&response).expect("json body");
  let users = json.as_array().expect("users array");
  assert!(
    users
      .iter()
      .any(|user| user.get("username").and_then(|value| value.as_str()) == Some("adm1")),
    "adm1 missing from user list"
  );
}

#[tokio::test]
async fn create_user_succeeds_with_unique_payload() {
  let token = login_and_get_token().await;
  let (id, username) = create_user_for_tests(&token).await;
  assert!(id > 0, "user id should be positive");
  assert!(!username.is_empty(), "username should be returned");
}

#[tokio::test]
async fn create_user_fails_with_duplicate_username() {
  let token = login_and_get_token().await;
  let body = json!({
    "username": "adm1",
    "password_hash": "adm1-hash",
    "name": "Admin Copy",
    "person_type": "N",
    "document_type": "DNI",
    "document_number": "00000001",
  })
  .to_string();
  let request = request_with_token("POST", "/users", &token, Some(&body));
  execute(request.as_bytes(), b"Failed to create user").await;
}

#[tokio::test]
async fn create_user_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("POST", "/users", &token, Some("{\"username\":\"only\"}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn get_user_returns_existing_user() {
  let token = login_and_get_token().await;
  let list_request = request_with_token("GET", "/users", &token, None);
  let list_response = execute(list_request.as_bytes(), b"\"username\":\"adm1\"").await;
  let json = parse_json(&list_response).expect("json body");
  let users = json.as_array().expect("users array");
  let adm1 = users
    .iter()
    .find(|user| user.get("username").and_then(|value| value.as_str()) == Some("adm1"))
    .expect("adm1 user present");
  let adm1_id = adm1
    .get("id")
    .and_then(|value| value.as_i64())
    .expect("adm1 id");
  let path = format!("/users/{}", adm1_id);
  let request = request_with_token("GET", &path, &token, None);
  let response = execute(request.as_bytes(), b"\"username\":\"adm1\"").await;
  let user = parse_json(&response).expect("json body");
  assert_eq!(user["id"].as_i64(), Some(adm1_id));
}

#[tokio::test]
async fn get_user_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/users/abc", &token, None);
  execute(request.as_bytes(), b"Invalid user ID").await;
}

#[tokio::test]
async fn get_user_returns_not_found() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/users/999999", &token, None);
  execute(request.as_bytes(), b"User not found").await;
}

#[tokio::test]
async fn update_user_succeeds_for_existing_user() {
  let token = login_and_get_token().await;
  let (user_id, _) = create_user_for_tests(&token).await;
  let update_body = json!({ "name": "Updated User" }).to_string();
  let path = format!("/users/{}", user_id);
  let request = request_with_token("PUT", &path, &token, Some(&update_body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");

  let verify_request = request_with_token("GET", &path, &token, None);
  let verify_response = execute(verify_request.as_bytes(), b"\"name\":\"Updated User\"").await;
  let user = parse_json(&verify_response).expect("json body");
  assert_eq!(user["name"], "Updated User");
}

#[tokio::test]
async fn update_user_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("PUT", "/users/1", &token, Some("{\"name\":}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn update_user_requires_token() {
  execute(b"PUT /users/1 HTTP/1.1\r\n\r\n", b"Missing token header").await;
}

#[tokio::test]
async fn delete_user_succeeds() {
  let token = login_and_get_token().await;
  let (user_id, _) = create_user_for_tests(&token).await;
  let path = format!("/users/{}", user_id);
  let request = request_with_token("DELETE", &path, &token, None);
  let response = execute(request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );

  let verify = request_with_token("GET", &path, &token, None);
  execute(verify.as_bytes(), b"User not found").await;
}

#[tokio::test]
async fn delete_user_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("DELETE", "/users/abc", &token, None);
  execute(request.as_bytes(), b"Invalid user ID").await;
}

#[tokio::test]
async fn delete_user_requires_token() {
  execute(b"DELETE /users/1 HTTP/1.1\r\n\r\n", b"Missing token header").await;
}

#[tokio::test]
async fn list_services_returns_data() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/services", &token, None);
  let response = execute(request.as_bytes(), b"\"name\"").await;
  let json = parse_json(&response).expect("json body");
  let services = json.as_array().expect("services array");
  assert!(!services.is_empty(), "expected at least one service");
}

#[tokio::test]
async fn create_service_succeeds_with_unique_payload() {
  let token = login_and_get_token().await;
  let (id, name) = create_service_for_tests(&token).await;
  assert!(id > 0, "service id should be positive");
  assert!(!name.is_empty(), "service name should be returned");
}

#[tokio::test]
async fn create_service_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("POST", "/services", &token, Some("{\"name\":10}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn update_service_succeeds() {
  let token = login_and_get_token().await;
  let (service_id, _) = create_service_for_tests(&token).await;
  let update_body = json!({ "description": "Updated service" }).to_string();
  let path = format!("/services/{}", service_id);
  let request = request_with_token("PUT", &path, &token, Some(&update_body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");
}

#[tokio::test]
async fn update_service_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("PUT", "/services/abc", &token, Some("{\"name\":\"X\"}"));
  execute(request.as_bytes(), b"Invalid service ID").await;
}

#[tokio::test]
async fn delete_service_succeeds() {
  let token = login_and_get_token().await;
  let (service_id, _) = create_service_for_tests(&token).await;
  let path = format!("/services/{}", service_id);
  let request = request_with_token("DELETE", &path, &token, None);
  let response = execute(request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );
}

#[tokio::test]
async fn delete_service_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("DELETE", "/services/abc", &token, None);
  execute(request.as_bytes(), b"Invalid service ID").await;
}

#[tokio::test]
async fn delete_service_requires_token() {
  execute(
    b"DELETE /services/1 HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn list_roles_returns_data() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/roles", &token, None);
  let response = execute(request.as_bytes(), b"\"name\"").await;
  let json = parse_json(&response).expect("json body");
  let roles = json.as_array().expect("roles array");
  assert!(
    roles
      .iter()
      .any(|role| role.get("name").and_then(|value| value.as_str()) == Some("Admin")),
    "Admin role missing in list"
  );
}

#[tokio::test]
async fn create_role_succeeds_with_unique_name() {
  let token = login_and_get_token().await;
  let (id, name) = create_role_for_tests(&token).await;
  assert!(id > 0, "role id should be positive");
  assert!(!name.is_empty(), "role name should be returned");
}

#[tokio::test]
async fn create_role_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("POST", "/roles", &token, Some("{\"title\":\"invalid\"}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn get_role_returns_created_role() {
  let token = login_and_get_token().await;
  let (role_id, role_name) = create_role_for_tests(&token).await;
  let path = format!("/roles/{}", role_id);
  let request = request_with_token("GET", &path, &token, None);
  let response = execute(request.as_bytes(), role_name.as_bytes()).await;
  let role = parse_json(&response).expect("json body");
  assert_eq!(role["id"].as_i64(), Some(role_id as i64));
}

#[tokio::test]
async fn get_role_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/roles/abc", &token, None);
  execute(request.as_bytes(), b"Invalid role ID").await;
}

#[tokio::test]
async fn update_role_succeeds() {
  let token = login_and_get_token().await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let new_name = unique_value("updated_role");
  let update_body = json!({ "name": new_name }).to_string();
  let path = format!("/roles/{}", role_id);
  let request = request_with_token("PUT", &path, &token, Some(&update_body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");
}

#[tokio::test]
async fn update_role_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("PUT", "/roles/1", &token, Some("{\"name\":}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn delete_role_succeeds() {
  let token = login_and_get_token().await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let path = format!("/roles/{}", role_id);
  let request = request_with_token("DELETE", &path, &token, None);
  let response = execute(request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );
}

#[tokio::test]
async fn delete_role_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("DELETE", "/roles/abc", &token, None);
  execute(request.as_bytes(), b"Invalid role ID").await;
}

#[tokio::test]
async fn delete_role_requires_token() {
  execute(b"DELETE /roles/1 HTTP/1.1\r\n\r\n", b"Missing token header").await;
}

#[tokio::test]
async fn list_permissions_returns_data() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/permissions", &token, None);
  let response = execute(request.as_bytes(), b"\"name\"").await;
  let json = parse_json(&response).expect("json body");
  let permissions = json.as_array().expect("permissions array");
  assert!(
    permissions
      .iter()
      .any(|permission| permission.get("name").and_then(|value| value.as_str()) == Some("read")),
    "read permission missing"
  );
}

#[tokio::test]
async fn create_permission_succeeds_with_unique_name() {
  let token = login_and_get_token().await;
  let (id, name) = create_permission_for_tests(&token).await;
  assert!(id > 0, "permission id should be positive");
  assert!(!name.is_empty(), "permission name should be returned");
}

#[tokio::test]
async fn create_permission_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token(
    "POST",
    "/permissions",
    &token,
    Some("{\"title\":\"invalid\"}"),
  );
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn update_permission_succeeds() {
  let token = login_and_get_token().await;
  let (permission_id, _) = create_permission_for_tests(&token).await;
  let new_name = unique_value("permission_updated");
  let update_body = json!({ "name": new_name }).to_string();
  let path = format!("/permissions/{}", permission_id);
  let request = request_with_token("PUT", &path, &token, Some(&update_body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");
}

#[tokio::test]
async fn update_permission_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token("PUT", "/permissions/1", &token, Some("{\"name\":}"));
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn delete_permission_succeeds() {
  let token = login_and_get_token().await;
  let (permission_id, _) = create_permission_for_tests(&token).await;
  let path = format!("/permissions/{}", permission_id);
  let request = request_with_token("DELETE", &path, &token, None);
  let response = execute(request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );
}

#[tokio::test]
async fn delete_permission_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("DELETE", "/permissions/abc", &token, None);
  execute(request.as_bytes(), b"Invalid permission ID").await;
}

#[tokio::test]
async fn delete_permission_requires_token() {
  execute(
    b"DELETE /permissions/1 HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn assign_permission_to_role_succeeds() {
  let token = login_and_get_token().await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let (permission_id, _) = create_permission_for_tests(&token).await;
  let body = json!({
    "role_id": role_id,
    "permission_id": permission_id,
  })
  .to_string();
  let request = request_with_token("POST", "/role-permissions", &token, Some(&body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");
}

#[tokio::test]
async fn assign_permission_to_role_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token(
    "POST",
    "/role-permissions",
    &token,
    Some("{\"role_id\":\"x\"}"),
  );
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn remove_permission_from_role_succeeds() {
  let token = login_and_get_token().await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let (permission_id, _) = create_permission_for_tests(&token).await;
  let body = json!({
    "role_id": role_id,
    "permission_id": permission_id,
  })
  .to_string();
  let assign_request = request_with_token("POST", "/role-permissions", &token, Some(&body));
  execute(assign_request.as_bytes(), b"\"status\":\"success\"").await;

  let remove_request = request_with_token("DELETE", "/role-permissions", &token, Some(&body));
  let response = execute(remove_request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );
}

#[tokio::test]
async fn remove_permission_from_role_requires_token() {
  execute(
    b"DELETE /role-permissions HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn assign_role_to_service_succeeds() {
  let token = login_and_get_token().await;
  let (service_id, _) = create_service_for_tests(&token).await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let body = json!({
    "service_id": service_id,
    "role_id": role_id,
  })
  .to_string();
  let request = request_with_token("POST", "/service-roles", &token, Some(&body));
  let response = execute(request.as_bytes(), b"\"status\":\"success\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["status"], "success");
}

#[tokio::test]
async fn assign_role_to_service_fails_with_invalid_body() {
  let token = login_and_get_token().await;
  let request = request_with_token(
    "POST",
    "/service-roles",
    &token,
    Some("{\"service\":\"x\"}"),
  );
  execute(request.as_bytes(), b"Invalid request body").await;
}

#[tokio::test]
async fn remove_role_from_service_succeeds() {
  let token = login_and_get_token().await;
  let (service_id, _) = create_service_for_tests(&token).await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let body = json!({
    "service_id": service_id,
    "role_id": role_id,
  })
  .to_string();
  let assign_request = request_with_token("POST", "/service-roles", &token, Some(&body));
  execute(assign_request.as_bytes(), b"\"status\":\"success\"").await;

  let remove_request = request_with_token("DELETE", "/service-roles", &token, Some(&body));
  let response = execute(remove_request.as_bytes(), b"204").await;
  let status = status_line(&response).unwrap_or_default().to_string();
  assert!(
    status.contains("204"),
    "expected 204 response, got {}",
    status
  );
}

#[tokio::test]
async fn remove_role_from_service_requires_token() {
  execute(
    b"DELETE /service-roles HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn list_role_permissions_returns_entries() {
  let token = login_and_get_token().await;
  let (role_id, _) = create_role_for_tests(&token).await;
  let (permission_id, permission_name) = create_permission_for_tests(&token).await;
  let body = json!({
    "role_id": role_id,
    "permission_id": permission_id,
  })
  .to_string();
  let assign_request = request_with_token("POST", "/role-permissions", &token, Some(&body));
  execute(assign_request.as_bytes(), b"\"status\":\"success\"").await;

  let path = format!("/roles/{}/permissions", role_id);
  let request = request_with_token("GET", &path, &token, None);
  let response = execute(request.as_bytes(), permission_name.as_bytes()).await;
  let json = parse_json(&response).expect("json body");
  let permissions = json.as_array().expect("permissions array");
  assert!(
    permissions.iter().any(
      |permission| permission.get("id").and_then(|value| value.as_i64())
        == Some(permission_id as i64)
    ),
    "assigned permission missing from role list"
  );
}

#[tokio::test]
async fn list_role_permissions_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/roles/abc/permissions", &token, None);
  execute(request.as_bytes(), b"Invalid role ID").await;
}

#[tokio::test]
async fn list_service_roles_returns_entries() {
  let token = login_and_get_token().await;
  let (service_id, _) = create_service_for_tests(&token).await;
  let (role_id, role_name) = create_role_for_tests(&token).await;
  let body = json!({
    "service_id": service_id,
    "role_id": role_id,
  })
  .to_string();
  let assign_request = request_with_token("POST", "/service-roles", &token, Some(&body));
  execute(assign_request.as_bytes(), b"\"status\":\"success\"").await;

  let path = format!("/services/{}/roles", service_id);
  let request = request_with_token("GET", &path, &token, None);
  let response = execute(request.as_bytes(), role_name.as_bytes()).await;
  let json = parse_json(&response).expect("json body");
  let roles = json.as_array().expect("roles array");
  assert!(
    roles
      .iter()
      .any(|role| role.get("id").and_then(|value| value.as_i64()) == Some(role_id as i64)),
    "assigned role missing from service list"
  );
}

#[tokio::test]
async fn list_service_roles_fails_with_invalid_id() {
  let token = login_and_get_token().await;
  let request = request_with_token("GET", "/services/abc/roles", &token, None);
  execute(request.as_bytes(), b"Invalid service ID").await;
}
