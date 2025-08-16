use std::env;

use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde::Serialize;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .nest_service("/assets", ServeDir::new("assets"))
        .route("/", get(root))
        .route("/protected", get(protected));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    login_link: String,
    logout_link: String,
}

async fn root() -> impl IntoResponse {
    let mut address = env::var("AUTH_SERVICE_IP").unwrap_or("localhost".to_owned());
    if address.is_empty() {
        address = "localhost".to_owned();
    }
    let login_link = format!("http://{}:3000", address);
    let logout_link = format!("http://{}:3000/logout", address);

    let template = IndexTemplate {
        login_link,
        logout_link,
    };
    Html(template.render().unwrap())
}

async fn protected(jar: CookieJar) -> impl IntoResponse {
    println!("=== PROTECTED ROUTE ACCESS ===");
    println!("All cookies: {:?}", jar);
    
    let jwt_cookie = match jar.get("jwt") {
        Some(cookie) => {
            println!("✅ JWT cookie found: {}", cookie.value());
            cookie
        },
        None => {
            println!("❌ No JWT cookie found in request");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let api_client = reqwest::Client::builder().build().unwrap();

    let verify_token_body = serde_json::json!({
        "token": &jwt_cookie.value(),
    });
    
    println!("🔍 Verifying token with auth service...");
    println!("Token: {}", jwt_cookie.value());

    let auth_hostname = env::var("AUTH_SERVICE_HOST_NAME").unwrap_or("0.0.0.0".to_owned());
    let url = format!("http://{}:3000/verify-token", auth_hostname);
    println!("Auth service URL: {}", url);

    let response = match api_client.post(&url).json(&verify_token_body).send().await {
        Ok(response) => {
            println!("✅ Auth service responded with status: {}", response.status());
            response
        },
        Err(e) => {
            println!("❌ Failed to call auth service: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::BAD_REQUEST => {
            println!("❌ Token verification failed - returning 401");
            StatusCode::UNAUTHORIZED.into_response()
        }
        reqwest::StatusCode::OK => {
            println!("✅ Token verification successful - returning protected content");
            Json(ProtectedRouteResponse {
                img_url: "https://i.ibb.co/YP90j68/Light-Live-Bootcamp-Certificate.png".to_owned(),
            })
            .into_response()
        }
        _ => {
            println!("❌ Unexpected auth service response: {}", response.status());
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Serialize)]
pub struct ProtectedRouteResponse {
    pub img_url: String,
}
