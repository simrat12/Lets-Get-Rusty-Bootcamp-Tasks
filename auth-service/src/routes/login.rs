use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use crate::domain::email::Email;
use crate::domain::password::Password;
use crate::domain::data_score::{LoginAttemptId, TwoFACode, TwoFACodeStore};
use crate::domain::EmailClient;
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

    // Get user and validate credentials
    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // Validate password
    if let Err(_) = user_store.validate_user(&email, &password).await {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }
    
    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&state, &user.email, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

// New!
async fn handle_2fa(
    state: &AppState,
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Generate a real login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();
    
    // Store the 2FA code in the store
    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    if let Err(_) = two_fa_code_store.add_code(email, &login_attempt_id, &two_fa_code).await {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Send 2FA code to user
    let email_client = state.email_client.read().await;
    if let Err(_) = email_client.send_email(email, "2FA code", &two_fa_code.as_ref()).await {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }
    
    (jar, Ok((StatusCode::PARTIAL_CONTENT, Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse { 
        message: "2FA required".to_string(), 
        login_attempt_id: login_attempt_id.as_ref().to_string() 
    })))))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Generate auth cookie only when 2FA is not required
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);
    (updated_jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}