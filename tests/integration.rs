use auth_api::auth_server;
use httpageboy::Server;
use httpageboy::test_utils::setup_test_server;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_server() -> Server {
  let _ = dotenvy::dotenv();
  let url = std::env::var("TEST_SERVER_URL").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
  auth_server(&url, 10).await
}

fn run_test(request: &[u8], expected_response: &[u8]) -> String {
  let server_url =
    std::env::var("TEST_SERVER_URL").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
  let mut stream = TcpStream::connect(server_url).expect("Failed to connect to server");

  stream.write_all(request).unwrap();
  stream.shutdown(std::net::Shutdown::Write).unwrap();

  let mut buffer = Vec::new();
  stream.read_to_end(&mut buffer).unwrap();

  let buffer_string = String::from_utf8_lossy(&buffer).to_string();
  let expected_response_string = String::from_utf8_lossy(expected_response).to_string();

  assert!(
    buffer_string.contains(&expected_response_string),
    "ASSERT FAILED:\n\nRECEIVED: {} \nEXPECTED: {} \n\n",
    buffer_string,
    expected_response_string
  );
  buffer_string
}

// Authentication

#[tokio::test]
async fn test_login_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
}

#[tokio::test]
async fn test_login_invalid_password() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"wrong\"}",
    b"invalid_credentials",
  );
}

#[tokio::test]
async fn test_logout_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let logout_request = format!("POST /auth/logout HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(logout_request.as_bytes(), b"\"status\":\"logged_out\"");
}

#[tokio::test]
async fn test_logout_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /auth/logout HTTP/1.1\r\n\r\n",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_profile_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let profile_request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(profile_request.as_bytes(), b"\"payload\"");
}

#[tokio::test]
async fn test_profile_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"GET /auth/profile HTTP/1.1\r\n\r\n",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_check_token_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let check_request = format!("POST /check-token HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(check_request.as_bytes(), b"\"valid\":true");
}

#[tokio::test]
async fn test_check_token_invalid_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /check-token HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"invalid_token",
  );
}

// Users

#[tokio::test]
async fn test_users_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /users HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"\"username\":\"adm1\"");
}

#[tokio::test]
async fn test_users_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /users HTTP/1.1\r\n\r\n", b"missing_token_header");
}

#[tokio::test]
async fn test_user_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_{}", suffix);
  let password = format!("pass_{}", suffix);
  let document = format!("{}", suffix);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Generated User",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let expected_username = format!("\"username\":\"{}\"", username);
  run_test(create_request.as_bytes(), expected_username.as_bytes());
}

#[tokio::test]
async fn test_user_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\ntest",
    token
  );
  run_test(create_request.as_bytes(), b"invalid_request_body");
}

#[tokio::test]
async fn test_user_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_update_{}", suffix);
  let password = format!("pass_update_{}", suffix);
  let document = format!("doc{}", suffix);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Update Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Updated User");
  let update_request = format!(
    "PUT /users/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = user_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_user_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /users/invalid-id HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Nobody\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"invalid_user_id");
}

#[tokio::test]
async fn test_user_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_delete_{}", suffix);
  let password = format!("pass_delete_{}", suffix);
  let document = format!("{}{}", suffix, 9);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Delete Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = user_id_segment,
    token = token
  );
  run_test(delete_request.as_bytes(), b"\"status\":\"user_deleted\"");
}

#[tokio::test]
async fn test_user_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /users/invalid-id HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"invalid_user_id");
}

#[tokio::test]
async fn test_user_get_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_get_{}", suffix);
  let password = format!("pass_get_{}", suffix);
  let document = format!("{}{}", suffix, 7);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Lookup Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let get_request = format!(
    "GET /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = user_id,
    token = token
  );
  let expected_username = format!("\"username\":\"{}\"", username);
  run_test(get_request.as_bytes(), expected_username.as_bytes());
}

#[tokio::test]
async fn test_user_get_not_found() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_get_missing_{}", suffix);
  let password = format!("pass_get_missing_{}", suffix);
  let document = format!("{}{}", suffix, 3);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Lookup Missing Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = &user_id,
    token = token
  );
  run_test(delete_request.as_bytes(), b"\"status\":\"user_deleted\"");

  let get_request = format!(
    "GET /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = user_id,
    token = token
  );
  run_test(get_request.as_bytes(), b"user_not_found");
}

// Services

#[tokio::test]
async fn test_services_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /services HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"Service A");
}

#[tokio::test]
async fn test_services_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /services HTTP/1.1\r\n\r\n", b"missing_token_header");
}

#[tokio::test]
async fn test_service_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("svc_{}", suffix);
  let create_body = format!(
    "{{\"name\":\"{name}\",\"description\":\"{desc}\"}}",
    name = service_name,
    desc = "Created via test"
  );
  let create_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let expected = format!("\"name\":\"{}\"", service_name);
  run_test(create_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_service_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n---",
    token
  );
  run_test(create_request.as_bytes(), b"invalid_request_body");
}

#[tokio::test]
async fn test_service_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("svc_update_{}", suffix);
  let create_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":null}}",
    token,
    name = service_name
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let service_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let update_request = format!(
    "PUT /services/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{{\"description\":\"Updated\"}}",
    id = service_id,
    token = token
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_service_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /services/not-a-number HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"description\":\"noop\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"invalid_service_id");
}

#[tokio::test]
async fn test_service_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("svc_delete_{}", suffix);
  let create_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":null}}",
    token,
    name = service_name
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let service_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /services/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = service_id,
    token = token
  );
  run_test(delete_request.as_bytes(), b"\"status\":\"service_deleted\"");
}

#[tokio::test]
async fn test_service_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /services/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"invalid_service_id");
}

// Roles

#[tokio::test]
async fn test_roles_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /roles HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"\"name\":\"Admin\"");
}

#[tokio::test]
async fn test_roles_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /roles HTTP/1.1\r\n\r\n", b"missing_token_header");
}

#[tokio::test]
async fn test_role_get_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_get_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let get_request = format!(
    "GET /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  run_test(get_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_role_get_not_found() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_missing_{}", suffix);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    token = token
  );
  run_test(delete_request.as_bytes(), b"\"status\":\"role_deleted\"");

  let get_request = format!(
    "GET /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    token = token
  );
  run_test(get_request.as_bytes(), b"role_not_found");
}

#[tokio::test]
async fn test_role_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  run_test(create_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_role_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n---",
    token
  );
  run_test(create_request.as_bytes(), b"invalid_request_body");
}

#[tokio::test]
async fn test_role_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_update_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Role Updated");
  let update_request = format!(
    "PUT /roles/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = role_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_role_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /roles/invalid HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Oops\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"invalid_role_id");
}

#[tokio::test]
async fn test_role_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_delete_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id_segment,
    token = token
  );
  run_test(delete_request.as_bytes(), b"\"status\":\"role_deleted\"");
}

#[tokio::test]
async fn test_role_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!("DELETE /roles/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(delete_request.as_bytes(), b"invalid_role_id");
}

// Permissions

#[tokio::test]
async fn test_permissions_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /permissions HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"\"name\":\"read\"");
}

#[tokio::test]
async fn test_permissions_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"GET /permissions HTTP/1.1\r\n\r\n",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_permission_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let expected = format!("\"name\":\"{}\"", permission_name);
  run_test(create_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_permission_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{",
    token
  );
  run_test(create_request.as_bytes(), b"invalid_request_body");
}

#[tokio::test]
async fn test_permission_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_update_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let permission_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Permission Updated");
  let update_request = format!(
    "PUT /permissions/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = permission_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_permission_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /permissions/invalid HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Oops\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"invalid_permission_id");
}

#[tokio::test]
async fn test_permission_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_delete_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let permission_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /permissions/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = permission_id_segment,
    token = token
  );
  run_test(
    delete_request.as_bytes(),
    b"\"status\":\"permission_deleted\"",
  );
}

#[tokio::test]
async fn test_permission_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /permissions/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"invalid_permission_id");
}

// Role-Permission relations

#[tokio::test]
async fn test_role_permissions_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_relation_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_relation_{}", suffix_permission);
  let create_permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, permission_name
  );
  let permission_response = run_test(create_permission_request.as_bytes(), b"\"id\"");
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("role_perm_service_{}", suffix_service);
  let service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Role perm\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let service_role_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id}}}",
    service_id = service_id.clone(),
    role_id = role_id.clone()
  );
  let service_role_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, service_role_body
  );
  run_test(service_role_request.as_bytes(), b"\"status\":\"success\"");

  let assign_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    service_id = service_id,
    role_id = role_id,
    permission_id = permission_id
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_role_permissions_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /role-permissions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"service_id\":1,\"role_id\":1,\"permission_id\":1}",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_role_permissions_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_list_perm_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("perm_list_{}", suffix_permission);
  let permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, permission_name
  );
  let permission_response = run_test(permission_request.as_bytes(), b"\"id\"");
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("role_perm_list_service_{}", suffix_service);
  let service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Role perm list\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let service_role_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id}}}",
    service_id = service_id.clone(),
    role_id = role_id.clone()
  );
  let service_role_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, service_role_body
  );
  run_test(service_role_request.as_bytes(), b"\"status\":\"success\"");

  let assign_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    service_id = service_id.clone(),
    role_id = role_id.clone(),
    permission_id = permission_id
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let list_request = format!(
    "GET /roles/{id}/permissions?service_id={service_id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    service_id = service_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", permission_name);
  run_test(list_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_role_permissions_list_invalid_role_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!(
    "GET /roles/invalid/permissions?service_id=1 HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(list_request.as_bytes(), b"invalid_role_id");
}

#[tokio::test]
async fn test_role_permissions_remove_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_remove_perm_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("perm_remove_{}", suffix_permission);
  let permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, permission_name
  );
  let permission_response = run_test(permission_request.as_bytes(), b"\"id\"");
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("role_perm_remove_service_{}", suffix_service);
  let service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Role perm remove\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let service_role_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id}}}",
    service_id = service_id.clone(),
    role_id = role_id.clone()
  );
  let service_role_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, service_role_body
  );
  run_test(service_role_request.as_bytes(), b"\"status\":\"success\"");

  let assign_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    service_id = service_id.clone(),
    role_id = role_id.clone(),
    permission_id = permission_id.clone()
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let remove_request = format!(
    "DELETE /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(
    remove_request.as_bytes(),
    b"\"status\":\"permission_removed_from_role\"",
  );
}

#[tokio::test]
async fn test_role_permissions_remove_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let remove_request = format!(
    "DELETE /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\nnot-json",
    token
  );
  run_test(remove_request.as_bytes(), b"invalid_request_body");
}

// Service-Roles relations

#[tokio::test]
async fn test_service_roles_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"{desc}\"}}",
    token,
    name = service_name,
    desc = "Assigned via test"
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_service_relation_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!("{{\"service_id\":{},\"role_id\":{}}}", service_id, role_id);
  let assign_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_service_roles_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_service_roles_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("svc_role_list_{}", suffix_service);
  let service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":null}}",
    token,
    name = service_name
  );
  let service_response = run_test(service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_for_service_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!("{{\"service_id\":{},\"role_id\":{}}}", service_id, role_id);
  let assign_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let list_request = format!(
    "GET /services/{id}/roles HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = service_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  run_test(list_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_service_roles_list_invalid_service_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!(
    "GET /services/invalid/roles HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(list_request.as_bytes(), b"invalid_service_id");
}

#[tokio::test]
async fn test_service_roles_remove_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("svc_role_remove_{}", suffix_service);
  let service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":null}}",
    token,
    name = service_name
  );
  let service_response = run_test(service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_remove_service_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!("{{\"service_id\":{},\"role_id\":{}}}", service_id, role_id);
  let assign_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let remove_request = format!(
    "DELETE /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(
    remove_request.as_bytes(),
    b"\"status\":\"role_removed_from_service\"",
  );
}

#[tokio::test]
async fn test_service_roles_remove_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let remove_request = format!(
    "DELETE /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, "{"
  );
  run_test(remove_request.as_bytes(), b"invalid_request_body");
}

// Person-Service-Roles relations

#[tokio::test]
async fn test_person_service_roles_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("psr_user_{}", suffix_user);
  let password = format!("psr_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 1);
  let create_user_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Relation User",
    doc = document
  );
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, create_user_body
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("PSR Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"{desc}\"}}",
    token,
    name = service_name,
    desc = "PSR test service"
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_role_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_person_service_roles_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /person-service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
    b"missing_token_header",
  );
}

#[tokio::test]
async fn test_person_service_roles_remove_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("psr_remove_user_{}", suffix_user);
  let password = format!("psr_remove_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 2);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"Remove User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("PSR Remove Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"removal\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_remove_role_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let remove_request = format!(
    "DELETE /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(
    remove_request.as_bytes(),
    b"\"status\":\"role_removed_from_person\"",
  );
}

#[tokio::test]
async fn test_person_service_roles_remove_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let remove_request = format!(
    "DELETE /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n-",
    token
  );
  run_test(remove_request.as_bytes(), b"invalid_request_body");
}

#[tokio::test]
async fn test_person_roles_in_service_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("psr_list_user_{}", suffix_user);
  let password = format!("psr_list_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 5);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"Role List User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("PSR Role List {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Role listing\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_role_list_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let list_request = format!(
    "GET /people/{person_id}/services/{service_id}/roles HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    person_id = user_id,
    service_id = service_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  run_test(list_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_person_roles_in_service_invalid_service_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let unique_username = format!("psr_invalid_{}", suffix_user);
  let unique_password = format!("psr_invalid_pass_{}", suffix_user);
  let unique_document = format!("{}{}", suffix_user, 1);
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"Temp\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = unique_username,
    pwd = unique_password,
    doc = unique_document
  );
  let user_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let list_request = format!(
    "GET /people/{person_id}/services/invalid/roles HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    person_id = user_id,
    token = token
  );
  run_test(list_request.as_bytes(), b"invalid_service_id");
}

#[tokio::test]
async fn test_persons_with_role_in_service_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("psr_people_list_{}", suffix_user);
  let password = format!("psr_people_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 8);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"People List User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("PSR People List {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"People listing\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_people_role_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let list_request = format!(
    "GET /services/{service_id}/roles/{role_id}/people HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    service_id = service_id,
    role_id = role_id,
    token = token
  );
  let expected = format!("\"username\":\"{}\"", username);
  run_test(list_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_persons_with_role_in_service_invalid_service_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_invalid_role_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let list_request = format!(
    "GET /services/invalid/roles/{role_id}/people HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    role_id = role_id,
    token = token
  );
  run_test(list_request.as_bytes(), b"invalid_service_id");
}

#[tokio::test]
async fn test_list_services_of_person_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("services_person_{}", suffix_user);
  let password = format!("services_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 4);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"Services Person\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("Person Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Person services\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let services_role_name = format!("services_role_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, services_role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");

  let list_request = format!(
    "GET /people/{person_id}/services HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    person_id = user_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", service_name);
  run_test(list_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_list_services_of_person_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!(
    "GET /people/invalid/services HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(list_request.as_bytes(), b"invalid_person_id");
}

#[tokio::test]
async fn test_check_permission_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("perm_user_{}", suffix_user);
  let password = format!("perm_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 6);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"Perm User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let perm_role_name = format!("perm_role_{}", suffix_role);
  let role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, perm_role_name
  );
  let role_response = run_test(role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("perm_check_{}", suffix_permission);
  let permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, permission_name
  );
  let permission_response = run_test(permission_request.as_bytes(), b"\"id\"");
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("Perm Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"Perm service\"}}",
    token,
    name = service_name
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let assign_service_body = format!("{{\"service_id\":{},\"role_id\":{}}}", service_id, role_id);
  let assign_service_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_service_body
  );
  run_test(assign_service_request.as_bytes(), b"\"status\":\"success\"");

  let assign_permission_body = format!(
    "{{\"service_id\":{service_id},\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    service_id = service_id,
    role_id = role_id,
    permission_id = permission_id
  );
  let assign_permission_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_permission_body
  );
  run_test(
    assign_permission_request.as_bytes(),
    b"\"status\":\"success\"",
  );

  let assign_person_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_person_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_person_body
  );
  run_test(assign_person_request.as_bytes(), b"\"status\":\"success\"");

  let check_body = format!(
    "{{\"person_id\":{person},\"service_id\":{service},\"permission_name\":\"{perm}\"}}",
    person = user_id,
    service = service_id,
    perm = permission_name
  );
  let check_request = format!(
    "GET /check-permission HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
    token,
    check_body.len(),
    check_body
  );
  run_test(check_request.as_bytes(), b"\"has_permission\":true");
}

#[tokio::test]
async fn test_check_permission_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let check_request = format!(
    "GET /check-permission HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n",
    token
  );
  run_test(check_request.as_bytes(), b"invalid_request_body");
}
