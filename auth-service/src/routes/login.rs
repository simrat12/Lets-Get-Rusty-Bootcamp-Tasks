use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use crate::domain::email::Email;
use crate::domain::password::Password;
use serde::{Deserialize, Serialize};
use axum_extra::extract::CookieJar;
use crate::utils::auth::generate_auth_cookie;

use crate::{
    AppState,
    domain::{error::AuthAPIError, user::User, data_score::UserStore},
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Parse email
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::MalformedInput)),
    };
    
    // Parse password  
    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::MalformedInput)),
    };
    
    let user_store = state.user_store.read().await;

    // Generate auth cookie
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);
    
    // Rest of the function stays the same...
    match user_store.get_user(&email).await {
        Ok(_) => {
            match user_store.validate_user(&email, &password).await {
                Ok(_) => (updated_jar, Ok(Json(LoginResponse { message: "Login successful".to_string() }))),
                Err(_) => (updated_jar, Err(AuthAPIError::IncorrectCredentials)),
            }
        },
        Err(_) => (updated_jar, Err(AuthAPIError::InvalidCredentials)),
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug, Deserialize, PartialEq)]
pub struct LoginResponse {
    pub message: String,
}