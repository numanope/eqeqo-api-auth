use auth_api::auth_server;

#[tokio::main]
async fn main() {
  let _ = dotenvy::dotenv();

  let server_url = std::env::var("SERVER_URL")
    .map(|url| {
      if let Some(stripped) = url.strip_prefix("http://") {
        stripped.to_string()
      } else if let Some(stripped) = url.strip_prefix("https://") {
        stripped.to_string()
      } else {
        url
      }
    })
    .or_else(|_| {
      std::env::var("SERVER_PORT").map(|port| format!("127.0.0.1:{}", port))
    })
    .unwrap_or_else(|_| "127.0.0.1:7878".to_string());

  let server = auth_server(&server_url, 10).await;
  server.run().await;
}
