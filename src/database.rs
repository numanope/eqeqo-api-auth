use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::env;
use tokio::sync::OnceCell;

#[derive(Clone)]
pub struct DB {
  pool: Pool<Postgres>,
}

static GLOBAL_POOL: OnceCell<Pool<Postgres>> = OnceCell::const_new();

impl DB {
  /// Create a pooled Postgres connection
  pub async fn new() -> Result<Self, sqlx::Error> {
    let pool = GLOBAL_POOL
      .get_or_try_init(|| async {
        // Fallback: intenta cargar .env si aún no se cargó
        let _ = dotenvy::dotenv();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let max_conns: u32 = env::var("MAX_CONNECTIONS")
          .ok()
          .and_then(|v| v.parse().ok())
          .unwrap_or(5);

        PgPoolOptions::new()
          .max_connections(max_conns)
          .connect(&database_url)
          .await
      })
      .await?
      .clone();

    Ok(Self { pool })
  }

  pub fn pool(&self) -> &Pool<Postgres> {
    &self.pool
  }
}
