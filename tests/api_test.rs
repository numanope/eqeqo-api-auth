use auth_api::{
  Server, create_server,
  test_utils::{run_test, setup_test_server},
};

const SERVER_URL: &str = "127.0.0.1:48080";

async fn test_auth_server() -> Server {
  create_server(SERVER_URL).await
}

async fn boot_server() {
  setup_test_server(Some(SERVER_URL), || test_auth_server()).await;
}

#[tokio::test]
async fn test_login_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_login_invalid_password() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"wrong\",\"service_id\":\"Service A\"}";
  let expected = b"invalid_credentials";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_login_missing_service() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}";
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_login_service_access_denied() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service B\"}";
  let expected = b"service_access_denied";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_logout_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let logout_request = format!("POST /auth/logout HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = logout_request.as_bytes();
  let expected = b"\"status\":\"logged_out\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_logout_missing_token() {
  boot_server().await;
  let request = b"POST /auth/logout HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_profile_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let profile_request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = profile_request.as_bytes();
  let expected = b"\"payload\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_profile_missing_token() {
  boot_server().await;
  let request = b"GET /auth/profile HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_token_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let check_request = format!("POST /check-token HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = check_request.as_bytes();
  let expected = b"\"valid\":true";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_token_service_mismatch() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('\"').next())
    .expect("token value")
    .to_string();

  let check_request = format!(
    "POST /check-token HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"service_id\":\"Service B\"}}",
    token
  );
  let request = check_request.as_bytes();
  let expected = b"service_mismatch";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_token_invalid_token() {
  boot_server().await;
  let request = b"POST /check-token HTTP/1.1\r\ntoken: invalid\r\n\r\n";
  let expected = b"invalid_token";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_token_missing_header() {
  boot_server().await;
  let request = b"POST /check-token HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Users

#[tokio::test]
async fn test_users_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /users HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = list_request.as_bytes();
  let expected = b"\"username\":\"adm1\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_users_list_missing_token() {
  boot_server().await;
  let request = b"GET /users HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_create_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = expected_username.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_create_missing_token() {
  boot_server().await;
  let request = b"POST /users HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"missing_token\",\"password_hash\":\"secret\",\"name\":\"No Auth\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"123\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_create_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_update_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_update_missing_token() {
  boot_server().await;
  let request =
    b"PUT /users/1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Nope\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_update_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"invalid_user_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_delete_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"user_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_delete_missing_token() {
  boot_server().await;
  let request = b"DELETE /users/1 HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_delete_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"invalid_user_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_get_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = get_request.as_bytes();
  let expected = expected_username.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_get_missing_token() {
  boot_server().await;
  let request = b"GET /users/1 HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_user_get_not_found() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"user_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let get_request = format!(
    "GET /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = user_id,
    token = token
  );
  let request = get_request.as_bytes();
  let expected = b"user_not_found";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Services

#[tokio::test]
async fn test_services_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /services HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = list_request.as_bytes();
  let expected = b"Service A";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_services_list_missing_token() {
  boot_server().await;
  let request = b"GET /services HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_create_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_create_missing_token() {
  boot_server().await;
  let request = b"POST /services HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"svc_missing\",\"description\":null}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_create_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_update_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_update_missing_token() {
  boot_server().await;
  let request = b"PUT /services/1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_update_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"invalid_service_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_delete_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"service_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_delete_missing_token() {
  boot_server().await;
  let request = b"DELETE /services/1 HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_delete_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"invalid_service_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Roles

#[tokio::test]
async fn test_roles_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /roles HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = list_request.as_bytes();
  let expected = b"\"name\":\"Admin\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_roles_list_missing_token() {
  boot_server().await;
  let request = b"GET /roles HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_get_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = get_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_get_not_found() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"role_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let get_request = format!(
    "GET /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    token = token
  );
  let request = get_request.as_bytes();
  let expected = b"role_not_found";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_create_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_create_missing_token() {
  boot_server().await;
  let request =
    b"POST /roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"missing_role\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_create_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_update_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_update_missing_token() {
  boot_server().await;
  let request =
    b"PUT /roles/1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"none\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_update_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"invalid_role_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_delete_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"role_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_delete_missing_token() {
  boot_server().await;
  let request = b"DELETE /roles/1 HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_delete_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!("DELETE /roles/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = delete_request.as_bytes();
  let expected = b"invalid_role_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Permissions

#[tokio::test]
async fn test_permissions_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /permissions HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let request = list_request.as_bytes();
  let expected = b"\"name\":\"read\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permissions_list_missing_token() {
  boot_server().await;
  let request = b"GET /permissions HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_create_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_create_missing_token() {
  boot_server().await;
  let request = b"POST /permissions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"perm_missing\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_create_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_update_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_update_missing_token() {
  boot_server().await;
  let request =
    b"PUT /permissions/1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"none\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_update_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = update_request.as_bytes();
  let expected = b"invalid_permission_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_delete_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let create_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"\"status\":\"permission_deleted\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_delete_missing_token() {
  boot_server().await;
  let request = b"DELETE /permissions/1 HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_permission_delete_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = delete_request.as_bytes();
  let expected = b"invalid_permission_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Role-Permission relations

#[tokio::test]
async fn test_role_permissions_assign_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"code\":\"{name}\",\"description\":\"Relation\"}}",
    token,
    name = permission_name
  );
  let request = create_permission_request.as_bytes();
  let expected = b"\"id\"";
  let permission_response = run_test(request, expected, Some(SERVER_URL)).await;
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    role_id = role_id,
    permission_id = permission_id
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_assign_missing_token() {
  boot_server().await;
  let request = b"POST /role-permissions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"role_id\":1,\"permission_id\":1}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = permission_request.as_bytes();
  let expected = b"\"id\"";
  let permission_response = run_test(request, expected, Some(SERVER_URL)).await;
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    role_id = role_id.clone(),
    permission_id = permission_id
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let list_request = format!(
    "GET /roles/{id}/permissions HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", permission_name);
  let request = list_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_list_missing_token() {
  boot_server().await;
  let request = b"GET /roles/1/permissions HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_list_invalid_role_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!(
    "GET /roles/invalid/permissions HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  let request = list_request.as_bytes();
  let expected = b"invalid_role_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_remove_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = permission_request.as_bytes();
  let expected = b"\"id\"";
  let permission_response = run_test(request, expected, Some(SERVER_URL)).await;
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"role_id\":{role_id},\"permission_id\":{permission_id}}}",
    role_id = role_id.clone(),
    permission_id = permission_id.clone()
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let remove_request = format!(
    "DELETE /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = remove_request.as_bytes();
  let expected = b"\"status\":\"permission_removed_from_role\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_role_permissions_remove_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = remove_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Service-Roles relations

#[tokio::test]
async fn test_service_roles_assign_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_assign_missing_token() {
  boot_server().await;
  let request = b"POST /service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let list_request = format!(
    "GET /services/{id}/roles HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = service_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  let request = list_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_list_missing_token() {
  boot_server().await;
  let request = b"GET /services/1/roles HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_list_invalid_service_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = list_request.as_bytes();
  let expected = b"invalid_service_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_remove_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let remove_request = format!(
    "DELETE /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = remove_request.as_bytes();
  let expected = b"\"status\":\"role_removed_from_service\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_service_roles_remove_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = remove_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

// Person-Service-Roles relations

#[tokio::test]
async fn test_person_service_roles_assign_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_service_permission_assign_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let username = format!("psp_user_{}", suffix_user);
  let password = format!("psp_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 11);
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"PSP User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    token,
    uname = username,
    pwd = password,
    doc = document
  );
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("psp_permission_{}", suffix_permission);
  let create_permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token, permission_name
  );
  let request = create_permission_request.as_bytes();
  let expected = b"\"id\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let grant_request = format!(
    "POST /person-service-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"person_id\":{},\"service_id\":\"Service A\",\"permission_name\":\"{}\"}}",
    token, user_id, permission_name
  );
  let request = grant_request.as_bytes();
  let expected = b"\"status\":\"permission_granted\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_service_permission_missing_token() {
  boot_server().await;
  let request =
    b"POST /person-service-permissions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_service_roles_assign_missing_token() {
  boot_server().await;
  let request = b"POST /person-service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_service_roles_remove_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let remove_request = format!(
    "DELETE /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_body
  );
  let request = remove_request.as_bytes();
  let expected = b"\"status\":\"role_removed_from_person\"";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_service_roles_remove_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = remove_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_roles_in_service_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let list_request = format!(
    "GET /people/{person_id}/services/{service_id}/roles HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    person_id = user_id,
    service_id = service_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  let request = list_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_roles_in_service_missing_token() {
  boot_server().await;
  let request = b"GET /people/1/services/1/roles HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_person_roles_in_service_invalid_service_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = list_request.as_bytes();
  let expected = b"invalid_service_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_persons_with_role_in_service_list_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let list_request = format!(
    "GET /services/{service_id}/roles/{role_id}/people HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    service_id = service_id,
    role_id = role_id,
    token = token
  );
  let expected = format!("\"username\":\"{}\"", username);
  let request = list_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_persons_with_role_in_service_missing_token() {
  boot_server().await;
  let request = b"GET /services/1/roles/1/people HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_persons_with_role_in_service_invalid_service_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = list_request.as_bytes();
  let expected = b"invalid_service_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_list_services_of_person_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let list_request = format!(
    "GET /people/{person_id}/services HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    person_id = user_id,
    token = token
  );
  let expected = format!("\"name\":\"{}\"", service_name);
  let request = list_request.as_bytes();
  let expected = expected.as_bytes();
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_list_services_of_person_missing_token() {
  boot_server().await;
  let request = b"GET /people/1/services HTTP/1.1\r\n\r\n";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_list_services_of_person_invalid_id() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = list_request.as_bytes();
  let expected = b"invalid_person_id";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_permission_success() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_user_request.as_bytes();
  let expected = b"\"id\"";
  let user_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = role_request.as_bytes();
  let expected = b"\"id\"";
  let role_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = permission_request.as_bytes();
  let expected = b"\"id\"";
  let permission_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = create_service_request.as_bytes();
  let expected = b"\"id\"";
  let service_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = assign_service_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

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
  let request = assign_permission_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

  let assign_person_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id, service_id, role_id
  );
  let assign_person_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token, assign_person_body
  );
  let request = assign_person_request.as_bytes();
  let expected = b"\"status\":\"success\"";
  run_test(request, expected, Some(SERVER_URL)).await;

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
  let request = check_request.as_bytes();
  let expected = b"\"has_permission\":true";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_permission_missing_token() {
  boot_server().await;
  let request = b"GET /check-permission HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"person_id\":1,\"service_id\":1,\"permission_name\":\"any\"}";
  let expected = b"missing_token_header";
  run_test(request, expected, Some(SERVER_URL)).await;
}

#[tokio::test]
async fn test_check_permission_invalid_body() {
  boot_server().await;
  let request = b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\",\"service_id\":\"Service A\"}";
  let expected = b"\"token\"";
  let login_response = run_test(request, expected, Some(SERVER_URL)).await;
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
  let request = check_request.as_bytes();
  let expected = b"invalid_request_body";
  run_test(request, expected, Some(SERVER_URL)).await;
}
