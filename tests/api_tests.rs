use auth_api::auth_server;
use httpageboy::test_utils::{SERVER_URL, run_test, setup_test_server};
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_server() -> Server {
  let _ = dotenvy::dotenv();

  let server = auth_server("127.0.0.1:7878", 10).await;
  server.run().await;
}

async fn ensure_test_server() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;
}

async fn execute(request: &[u8], expected: &[u8]) {
  ensure_test_server().await;
  run_test(request, expected);
}

#[tokio::test]
async fn test_home() {
  execute(b"GET / HTTP/1.1\r\n\r\n", b"Welcome to the Auth API").await;
}

#[tokio::test]
async fn test_list_users_success() {
  execute(b"GET /users HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n", b"[]").await;
}

#[tokio::test]
async fn test_get_user_not_found() {
  execute(
    b"GET /users/999 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"User not found",
  )
  .await;
}

#[tokio::test]
async fn test_create_user_success() {
  execute(
    b"POST /users HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"username\":\"testuser\",\"password_hash\":\"hash\",\"name\":\"Test User\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"12345678\"}",
    b"\"username\":\"testuser\"",
  )
  .await;
}

#[tokio::test]
async fn test_update_user_invalid_id() {
  execute(
    b"PUT /users/abc HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"username\":\"x\"}",
    b"Invalid user ID",
  )
  .await;
}

#[tokio::test]
async fn test_delete_user_success() {
  execute(
    b"POST /users HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"username\":\"todelete\",\"password_hash\":\"p\",\"name\":\"To Delete\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"87654321\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"DELETE /users/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_list_services() {
  execute(
    b"GET /services HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_create_service_missing_body() {
  execute(
    b"POST /services HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"Invalid request body",
  )
  .await;
}

#[tokio::test]
async fn test_update_service() {
  execute(
    b"POST /services HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"service1\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"PUT /services/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"svc\"}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_delete_service_not_found() {
  execute(
    b"DELETE /services/999 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"Failed to delete service",
  )
  .await;
}

#[tokio::test]
async fn test_list_roles() {
  execute(b"GET /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n", b"[]").await;
}

#[tokio::test]
async fn test_get_role_success() {
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"role1\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"GET /roles/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"\"name\":\"role1\"",
  )
  .await;
}

#[tokio::test]
async fn test_create_role_conflict() {
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"existing\"}",
    b"\"name\":\"existing\"",
  )
  .await;
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"existing\"}",
    b"Failed to create role",
  )
  .await;
}

#[tokio::test]
async fn test_update_role() {
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"role2\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"PUT /roles/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"new\"}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_delete_role() {
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"role3\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"DELETE /roles/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_list_permissions() {
  execute(
    b"GET /permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_create_permission() {
  execute(
    b"POST /permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"p\"}",
    b"\"name\":\"p\"",
  )
  .await;
}

#[tokio::test]
async fn test_update_permission() {
  execute(
    b"POST /permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"p1\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"PUT /permissions/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"p2\"}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_delete_permission() {
  execute(
    b"POST /permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"p3\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"DELETE /permissions/1 HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_assign_permission_to_role() {
  execute(
    b"POST /roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"role_for_perm\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"POST /permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"name\":\"perm_for_role\"}",
    b"\"id\":1",
  )
  .await;
  execute(
    b"POST /role-permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"role_id\":1,\"permission_id\":1}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_remove_permission_from_role() {
  execute(
    b"DELETE /role-permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"role_id\":1,\"permission_id\":1}",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_list_role_permissions() {
  execute(
    b"GET /roles/1/permissions HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_assign_role_to_service() {
  execute(
    b"POST /service-roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"service_id\":1,\"role_id\":1}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_remove_role_from_service() {
  execute(
    b"DELETE /service-roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"service_id\":1,\"role_id\":1}",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_list_service_roles() {
  execute(
    b"GET /services/1/roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_assign_role_to_person_in_service() {
  execute(
    b"POST /person-service-roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"person_id\":1,\"service_id\":1,\"role_id\":1}",
    b"success",
  )
  .await;
}

#[tokio::test]
async fn test_remove_role_from_person_in_service() {
  execute(
    b"DELETE /person-service-roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"person_id\":1,\"service_id\":1,\"role_id\":1}",
    b"",
  )
  .await;
}

#[tokio::test]
async fn test_list_person_roles_in_service() {
  execute(
    b"GET /people/1/services/1/roles HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_list_persons_with_role_in_service() {
  execute(
    b"GET /services/1/roles/1/people HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}

#[tokio::test]
async fn test_check_person_permission_in_service() {
  execute(
    b"POST /check-permission HTTP/1.1\r\ntoken: VALID_TOKEN\r\nContent-Type: application/json\r\n\r\n{\"person_id\":1,\"service_id\":1,\"permission_name\":\"read\"}",
    b"\"has_permission\":false",
  )
  .await;
}

#[tokio::test]
async fn test_list_services_of_person() {
  execute(
    b"GET /people/1/services HTTP/1.1\r\ntoken: VALID_TOKEN\r\n\r\n",
    b"[]",
  )
  .await;
}
