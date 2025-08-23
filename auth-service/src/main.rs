use auth_service::{Application, get_postgres_pool, get_redis_client};
use auth_service::data_stores::data_store::{BannedTokenStoreType, TwoFACodeStore, UserStore};
use auth_service::data_stores::redis_two_fa_code_store::RedisTwoFACodeStore;
use auth_service::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::data_stores::redis_banned_token_store::RedisBannedTokenStore;
use auth_service::app_state::app_state::AppState;
use auth_service::services::mock_email_client::MockEmailClient;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::response::Html;
use auth_service::utils::constants::{prod, DATABASE_URL, REDIS_HOST_NAME};
use sqlx::PgPool;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;


    let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool)) as Box<dyn UserStore + Send + Sync>));
    let banned_token_store = Arc::new(RwLock::new(BannedTokenStoreType::Redis(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis()))))));
    let two_fa_code_store = Arc::new(RwLock::new(Box::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())))) as Box<dyn TwoFACodeStore + Send + Sync>));
    let email_client = Arc::new(RwLock::new(Box::new(MockEmailClient::default()) as Box<dyn auth_service::domain::EmailClient + Send + Sync>));
    let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);

    let app = Application::build(app_state, &prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn hello_handler() -> Html<&'static str> {
    // TODO: Update this to a custom message!
    Html("<h1>Hello, World! This is my first real attempt at Rust from scratch.</h1>")
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
