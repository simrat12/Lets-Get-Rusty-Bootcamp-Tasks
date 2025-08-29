use std::error::Error;
use crate::app_state::AppState;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use crate::utils::tracing::{make_span_with_request_id, on_request, on_response};

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use crate::domain::error::AuthAPIError;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use redis::{Client, RedisResult};

pub mod routes;
pub mod services;
pub mod domain;
pub mod app_state;
pub mod utils;
pub mod data_stores;


#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::MalformedInput => (StatusCode::UNPROCESSABLE_ENTITY, "Malformed input"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            // TODO: Replace [YOUR_DROPLET_IP] with your Droplet IP address
            "http://[YOUR_DROPLET_IP]:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);


        let router = Router::new()
        .nest_service("/", ServeDir::new("assets"))
        .route("/signup", post(routes::signup))
        .route("/login", post(routes::login))
        .route("/logout", post(routes::logout))
        .route("/verify-2fa", post(routes::verify_2fa))
        .route("/verify-token", post(routes::verify_token))
        .with_state(app_state)
        .layer(cors)
        .layer( // New!
            // Add a TraceLayer for HTTP requests to enable detailed tracing
            // This layer will create spans for each request using the make_span_with_request_id function,
            // and log events at the start and end of each request using on_request and on_response functions.
            TraceLayer::new_for_http()
                .make_span_with(make_span_with_request_id)
                .on_request(on_request)
                .on_response(on_response),
        );

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        tracing::info!("listening on {}", &self.address);
        self.server.await
    }
}

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool
    println!("🔗 Attempting to connect to PostgreSQL at: {}", url);
    let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
    println!("✅ PostgreSQL connection pool created successfully");
    Ok(pool)
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}:6379/", redis_hostname);
    println!("🔗 Attempting to connect to Redis at: {}", redis_url);
    let client = redis::Client::open(redis_url)?;
    println!("✅ Redis client created successfully");
    Ok(client)
}