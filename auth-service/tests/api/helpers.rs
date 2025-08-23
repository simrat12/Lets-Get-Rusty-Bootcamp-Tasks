use auth_service::{Application, get_postgres_pool, get_redis_client};
use uuid::Uuid;
use auth_service::data_stores::data_store::{UserStore, BannedTokenStoreType, TwoFACodeStore, BannedTokenStore};
use auth_service::data_stores::redis_two_fa_code_store::RedisTwoFACodeStore;
use auth_service::data_stores::redis_banned_token_store::RedisBannedTokenStore;
use auth_service::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::services::mock_email_client::MockEmailClient;
use auth_service::app_state::app_state::AppState;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::cookie::Jar;
use auth_service::utils::constants::{test, DATABASE_URL, REDIS_HOST_NAME};
use sqlx::{PgPool, postgres::{PgPoolOptions, PgConnectOptions, PgConnection}, Connection, Executor};
use std::str::FromStr;

// Define Body type for the generic parameter
type Body = serde_json::Value;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub app_state: AppState, // Add this field
    pub db_name: String,
    pub clean_up_called: bool,
}

impl TestApp {
    pub async fn new() -> Self {
        println!("🚀 Creating new TestApp...");
        
        let (pg_pool, db_name) = configure_postgresql().await;
        println!("✅ PostgreSQL pool configured");

        let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool)) as Box<dyn UserStore + Send + Sync>));
        println!("✅ User store configured");

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();
        println!("✅ HTTP client configured");

        println!("🔧 Configuring Redis stores...");
        let banned_token_store = Arc::new(RwLock::new(BannedTokenStoreType::Redis(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis()))))));
        let two_fa_code_store = Arc::new(RwLock::new(Box::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())))) as Box<dyn TwoFACodeStore + Send + Sync>));
        println!("✅ Redis stores configured");

        let email_client = Arc::new(RwLock::new(Box::new(MockEmailClient::default()) as Box<dyn auth_service::domain::EmailClient + Send + Sync>));
        let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);
        println!("✅ App state configured");

        println!("🔧 Building application...");
        let app = Application::build(app_state.clone(), &test::APP_ADDRESS) // Clone the app_state
            .await
            .expect("Failed to build app");
        println!("✅ Application built successfully");

        let address = format!("http://{}", app.address.clone());
        println!("🌐 Application address: {}", address);

        // Run the auth service in a separate async task
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());
        println!("✅ Application started in background");

        // Create new `TestApp` instance and return it
        println!("✅ TestApp creation completed");
        TestApp {
            address,
            cookie_jar,
            http_client,
            app_state, // Store the app_state
            db_name,
            clean_up_called: false,
        }
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }


    pub async fn verify_token(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // Add a method to check if a token is banned
    pub async fn is_token_banned(&self, token: &str) -> bool {
        let banned_token_store = self.app_state.banned_token_store.read().await;
        banned_token_store.is_token_banned(token).await.unwrap_or(false)
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn clean_up(&mut self) {
        self.clean_up_called = true;
        let db_name = self.db_name.clone();
        delete_database(&db_name).await;
    }

}

impl Drop for TestApp {
    fn drop(&mut self) {
        // Panic if clean_up has not been called
        if !self.clean_up_called {
            panic!("TestApp was dropped without calling clean_up() first!");
        }
        
        // Call the original clean_up method
        self.clean_up();
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql() -> (PgPool, String) {
    println!("🔧 Configuring PostgreSQL connection...");
    let postgresql_conn_url = DATABASE_URL.to_owned();
    println!("🔗 PostgreSQL base URL: {}", postgresql_conn_url);

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!
    let db_name = Uuid::new_v4().to_string();
    println!("📝 Creating test database: {}", db_name);

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);
    println!("🔗 PostgreSQL full URL: {}", postgresql_conn_url_with_db);

    // Create a new connection pool and return it
    let pg_pool = get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!");

    println!("✅ PostgreSQL configuration completed successfully");
    (pg_pool, db_name)
}

fn configure_redis() -> redis::Connection {
    println!("🔧 Configuring Redis connection...");
    match get_redis_client(REDIS_HOST_NAME.to_owned()) {
        Ok(client) => {
            println!("✅ Redis client created, attempting to get connection...");
            match client.get_connection() {
                Ok(conn) => {
                    println!("✅ Redis connection established successfully");
                    conn
                },
                Err(e) => {
                    eprintln!("❌ Failed to get Redis connection: {}", e);
                    eprintln!("Make sure Redis is running with: docker run --name redis-db -p 6379:6379 -d redis:7.0-alpine");
                    panic!("Redis connection failed");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get Redis client: {}", e);
            eprintln!("Make sure Redis is running with: docker run --name redis-db -p 6379:6379 -d redis:7.0-alpine");
            panic!("Redis client failed");
        }
    }
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    sqlx::query(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .execute(&connection)
        .await
        .expect("Failed to create database.");


    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}
