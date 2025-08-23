use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use crate::{AuthAPIError, AppState};
use crate::domain::email::Email;
use crate::data_stores::data_store::{LoginAttemptId, TwoFACode};
use serde::Deserialize;
use crate::utils::constants::JWT_COOKIE_NAME;
use crate::utils::auth::generate_auth_cookie;
use axum_extra::extract::CookieJar;

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {

    println!("=== 2FA VERIFICATION START ===");
    println!("Request: {:?}", request);
    
    println!("Request email: '{}'", request.email);
    println!("Request loginAttemptId: '{}'", request.loginAttemptId);
    println!("Request twoFactorCode: '{}'", request.two_factor_code);

    let email = match Email::parse(request.email) {
        Ok(email) => {
            println!("✅ Email parsed successfully: {}", email.as_ref());
            email
        },
        Err(_) => {
            println!("❌ Email parsing failed");
            return (jar, Err(AuthAPIError::InvalidCredentials))
        }
    };

    let login_attempt_id = match LoginAttemptId::parse(request.loginAttemptId) {
        Ok(login_attempt_id) => {
            println!("✅ Login attempt ID parsed successfully: {}", login_attempt_id.as_ref());
            login_attempt_id
        },
        Err(_) => {
            println!("❌ Login attempt ID parsing failed");
            return (jar, Err(AuthAPIError::InvalidCredentials))
        }
    };

    let two_fa_code = match TwoFACode::parse(request.two_factor_code) {
        Ok(two_fa_code) => {
            println!("✅ 2FA code parsed successfully: {}", two_fa_code.as_ref());
            two_fa_code
        },
        Err(_) => {
            println!("❌ 2FA code parsing failed");
            return (jar, Err(AuthAPIError::InvalidCredentials))
        }
    };

    // Verify the 2FA code against stored data
    println!("🔍 Checking 2FA code in store...");
    {
        let two_fa_store = state.two_fa_code_store.read().await;
        match two_fa_store.get_code(&email).await {
            Ok((stored_login_attempt_id, stored_code)) => {
                println!("✅ Found stored code for email: {}", email.as_ref());
                println!("   Stored login attempt ID: {}", stored_login_attempt_id.as_ref());
                println!("   Stored 2FA code: {}", stored_code.as_ref());
                println!("   Provided login attempt ID: {}", login_attempt_id.as_ref());
                println!("   Provided 2FA code: {}", two_fa_code.as_ref());
                
                if stored_login_attempt_id != login_attempt_id || stored_code != two_fa_code {
                    println!("❌ 2FA verification failed - credentials don't match");
                    return (jar, Err(AuthAPIError::IncorrectCredentials));
                }
                println!("✅ 2FA credentials match!");
            },
            Err(_) => {
                println!("❌ No stored 2FA code found for email: {}", email.as_ref());
                return (jar, Err(AuthAPIError::IncorrectCredentials))
            }
        }
    }

    // Remove the 2FA code from store after successful verification
    println!("🗑️ Removing 2FA code from store...");
    {
        let mut two_fa_store = state.two_fa_code_store.write().await;
        if let Err(_) = two_fa_store.remove_code(&email).await {
            println!("❌ Failed to remove 2FA code from store");
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
        println!("✅ 2FA code removed from store");
    }

    // Generate auth cookie for successful 2FA verification
    println!("🍪 Generating auth cookie...");
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => {
            println!("✅ Auth cookie generated successfully");
            println!("   Cookie name: {}", cookie.name());
            println!("   Cookie domain: {:?}", cookie.domain());
            println!("   Cookie path: {:?}", cookie.path());
            cookie
        },
        Err(_) => {
            println!("❌ Failed to generate auth cookie");
            return (jar, Err(AuthAPIError::UnexpectedError))
        }
    };

    let updated_jar = jar.add(auth_cookie);
    println!("✅ 2FA verification successful! Returning 200 OK");
    println!("=== 2FA VERIFICATION END ===");
    (updated_jar, Ok((StatusCode::OK, Json("2FA verification successful"))))
}

// TODO: implement the Verify2FARequest struct. See the verify-2fa route contract in step 1 for the expected JSON body.

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    pub loginAttemptId: String,
    #[serde(rename = "2FACode")]
    pub two_factor_code: String
}