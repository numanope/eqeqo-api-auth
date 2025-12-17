use crate::auth::TokenManager;
use crate::database::DB;
use crate::handlers::*;
pub mod auth;
mod database;
mod handlers;
pub use httpageboy::{Request, Response, Rt, Server, StatusCode, handler};
use std::sync::OnceLock;
use tokio::time::{self, Duration};

pub mod test_utils {
  pub use httpageboy::test_utils::{run_test, setup_test_server};
}

pub fn active_test_server_url() -> &'static str {
  httpageboy::test_utils::active_test_server_url()
}

fn build_cors_policy() -> httpageboy::CorsPolicy {
  let mut policy = httpageboy::CorsPolicy::default();

  if let Ok(origins) = std::env::var("CORS") {
    if !origins.trim().is_empty() {
      policy.allow_origin = origins;
    }
  }

  let mut headers: Vec<String> = policy
    .allow_headers
    .split(',')
    .map(|h| h.trim().to_string())
    .filter(|h| !h.is_empty())
    .collect();

  let mut push_unique = |value: &str| {
    if !headers.iter().any(|h| h.eq_ignore_ascii_case(value)) {
      headers.push(value.to_string());
    }
  };

  push_unique("token");
  if let Ok(extra) = std::env::var("CORS_HEADERS") {
    for header in extra.split(',').map(|h| h.trim()).filter(|h| !h.is_empty()) {
      push_unique(header);
    }
  }

  policy.allow_headers = headers.join(", ");
  policy
}

static CLEANUP_JOB_STARTED: OnceLock<()> = OnceLock::new();

fn spawn_cleanup_job() {
  if CLEANUP_JOB_STARTED.set(()).is_err() {
    return;
  }
  tokio::spawn(async move {
    let mut ticker = time::interval(Duration::from_secs(60));
    loop {
      ticker.tick().await;
      match DB::new().await {
        Ok(db) => {
          let manager = TokenManager::new(db.pool());
          if let Err(err) = manager.cleanup_expired().await {
            eprintln!("[cleanup] token cleanup failed: {}", err);
          }
        }
        Err(err) => eprintln!("[cleanup] db unavailable: {}", err),
      }
    }
  });
}

pub async fn create_server(server_url: &str) -> Server {
  let mut server = Server::new(server_url, None)
    .await
    .expect("Failed to create server");

  server.set_cors(build_cors_policy());
  spawn_cleanup_job();

  server.add_route("/", Rt::GET, handler!(home));

  // Auth
  server.add_route("/auth/login", Rt::POST, handler!(login));
  server.add_route("/auth/logout", Rt::POST, handler!(logout));
  server.add_route("/auth/profile", Rt::GET, handler!(profile));
  server.add_route("/check-token", Rt::POST, handler!(check_token));

  // Users
  server.add_route("/users", Rt::GET, handler!(list_people));
  server.add_route("/users", Rt::POST, handler!(create_user));
  server.add_route("/users/{id}", Rt::GET, handler!(get_user));
  server.add_route("/users/{id}", Rt::PUT, handler!(update_user));
  server.add_route("/users/{id}", Rt::DELETE, handler!(delete_user));

  // Services
  server.add_route("/services", Rt::GET, handler!(list_services));
  server.add_route("/services", Rt::POST, handler!(create_service));
  server.add_route("/services/{id}", Rt::PUT, handler!(update_service));
  server.add_route("/services/{id}", Rt::DELETE, handler!(delete_service));

  // Roles
  server.add_route("/roles", Rt::GET, handler!(list_roles));
  server.add_route("/roles", Rt::POST, handler!(create_role));
  server.add_route("/roles/{id}", Rt::GET, handler!(get_role));
  server.add_route("/roles/{id}", Rt::PUT, handler!(update_role));
  server.add_route("/roles/{id}", Rt::DELETE, handler!(delete_role));

  // Permissions
  server.add_route("/permissions", Rt::GET, handler!(list_permissions));
  server.add_route("/permissions", Rt::POST, handler!(create_permission));
  server.add_route("/permissions/{id}", Rt::PUT, handler!(update_permission));
  server.add_route("/permissions/{id}", Rt::DELETE, handler!(delete_permission));

  // Role-Permissions
  server.add_route(
    "/role-permissions",
    Rt::POST,
    handler!(assign_permission_to_role),
  );
  server.add_route(
    "/role-permissions",
    Rt::DELETE,
    handler!(remove_permission_from_role),
  );
  server.add_route(
    "/roles/{id}/permissions",
    Rt::GET,
    handler!(list_role_permissions),
  );

  // Service-Roles
  server.add_route("/service-roles", Rt::POST, handler!(assign_role_to_service));
  server.add_route(
    "/service-roles",
    Rt::DELETE,
    handler!(remove_role_from_service),
  );
  server.add_route(
    "/services/{id}/roles",
    Rt::GET,
    handler!(list_service_roles),
  );

  // Person-Service-Roles
  server.add_route(
    "/person-service-roles",
    Rt::POST,
    handler!(assign_role_to_person_in_service),
  );
  server.add_route(
    "/person-service-roles",
    Rt::DELETE,
    handler!(remove_role_from_person_in_service),
  );
  server.add_route(
    "/person-service-permissions",
    Rt::POST,
    handler!(grant_permission_to_person_in_service),
  );
  server.add_route(
    "/people/{person_id}/services/{service_id}/roles",
    Rt::GET,
    handler!(list_person_roles_in_service),
  );
  server.add_route(
    "/services/{service_id}/roles/{role_id}/people",
    Rt::GET,
    handler!(list_persons_with_role_in_service),
  );
  server.add_route(
    "/people/{person_id}/services",
    Rt::GET,
    handler!(list_services_of_person),
  );
  server.add_route(
    "/people/{person_id}/services/{service_id}",
    Rt::GET,
    handler!(get_person_service_info),
  );

  server
}
