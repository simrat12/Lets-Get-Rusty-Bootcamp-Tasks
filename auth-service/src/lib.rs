use axum::serve::Serve;
use axum::Router;
use std::error::Error;
use tower_http::services::ServeDir;
use axum::response::{Html, IntoResponse};
use axum::routing::post;
use axum::http::StatusCode;
pub mod routes;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let router = Router::new()
        .nest_service("/", ServeDir::new("assets"))
        .route("/signup", post(routes::signup))
        .route("/login", post(routes::login))
        .route("/logout", post(routes::logout))
        .route("/verify-2fa", post(routes::verify_2fa))
        .route("/verify-token", post(routes::verify_token));

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}