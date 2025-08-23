use crate::helpers::TestApp;
use auth_service::routes::TwoFactorAuthResponse;
use auth_service::domain::email::Email;
use auth_service::utils::constants::JWT_COOKIE_NAME;

#[tokio::test]
async fn verify_2fa_returns_200() {
    let mut app = TestApp::new().await;

    // First signup a user with 2FA enabled
    app.signup(&serde_json::json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    })).await;

    // Login to get 2FA code
    let login_response = app.login(&serde_json::json!({
        "email": "test@example.com",
        "password": "password123"
    })).await;

    let two_fa_response = login_response.json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");

    // Get the actual 2FA code from the store
    let email = Email::parse("test@example.com".to_string()).unwrap();
    let two_fa_code_store = app.app_state.two_fa_code_store.read().await;
    let (_, stored_code) = two_fa_code_store.get_code(&email).await.unwrap();
    let actual_code = stored_code.as_ref().to_string();
    drop(two_fa_code_store); // Release the read lock before calling verify_2fa

    // Verify 2FA with correct credentials
    let verify_response = app.post_verify_2fa(&serde_json::json!({
        "email": "test@example.com",
        "loginAttemptId": two_fa_response.login_attempt_id,
        "2FACode": actual_code
    })).await;

    assert_eq!(verify_response.status().as_u16(), 200);
    let cookies = verify_response.headers().get("set-cookie").unwrap();
    assert!(cookies.to_str().unwrap().contains(JWT_COOKIE_NAME));
    
    app.clean_up().await;
}


#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let response = app.post_verify_2fa(&serde_json::json!({})).await;

    assert_eq!(response.status().as_u16(), 422);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let response = app.post_verify_2fa(&serde_json::json!({
        "email": "invalid-email-format",
        "loginAttemptId": "invalid-login-attempt-id",
        "2FACode": "invalid-two-factor-code"
    })).await;

    assert_eq!(response.status().as_u16(), 400);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let response = app.post_verify_2fa(&serde_json::json!({
        "email": "test@example.com",
        "loginAttemptId": "123e4567-e89b-12d3-a456-426614174000",
        "2FACode": "123456"
    })).await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail. 
    let mut app = TestApp::new().await;

    app.signup(&serde_json::json!({
        "email": "test123@example.com",
        "password": "password123",
        "requires2FA": true
    })).await;

    let response = app.login(&serde_json::json!({
        "email": "test123@example.com",
        "password": "password123"
    })).await;

    let first_login_response = response.json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");
    
    let first_login_attempt_id = first_login_response.login_attempt_id;
    
    // Get the actual 2FA code from the first login BEFORE the second login overwrites it
    let email = Email::parse("test123@example.com".to_string()).unwrap();
    let two_fa_code_store = app.app_state.two_fa_code_store.read().await;
    let (_, first_stored_code) = two_fa_code_store.get_code(&email).await.unwrap();
    let first_actual_code = first_stored_code.as_ref().to_string();
    
    // Drop the read lock before the second login
    drop(two_fa_code_store);
    
    // Call login again to get a new 2FA code (this will overwrite the old one)
    let second_response = app.login(&serde_json::json!({
        "email": "test123@example.com",
        "password": "password123"
    })).await;
    
    let second_login_response = second_response.json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");
    
    // Try to verify with the old login attempt ID and the actual old code
    // Since the old code was overwritten by the second login, this should fail
    let verify_response = app.post_verify_2fa(&serde_json::json!({
        "email": "test123@example.com",
        "loginAttemptId": first_login_attempt_id,
        "2FACode": first_actual_code // Use the actual old code
    })).await;
    
    assert_eq!(verify_response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let mut app = TestApp::new().await;

    app.signup(&serde_json::json!({
        "email": "test123@example.com",
        "password": "password123",
        "requires2FA": true
    })).await;

    // Single login - generates one 2FA code
    let response = app.login(&serde_json::json!({
        "email": "test123@example.com",
        "password": "password123"
    })).await;
    
    let login_response = response.json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");

    let login_attempt_id = login_response.login_attempt_id;

    // Get the 2FA code
    let email = Email::parse("test123@example.com".to_string()).unwrap();
    let two_fa_code_store = app.app_state.two_fa_code_store.read().await;
    let (_, stored_code) = two_fa_code_store.get_code(&email).await.unwrap();
    let actual_code = stored_code.as_ref().to_string();
    drop(two_fa_code_store);

    // First verification - should succeed
    let first_verify_response = app.post_verify_2fa(&serde_json::json!({
        "email": "test123@example.com",
        "loginAttemptId": login_attempt_id,
        "2FACode": actual_code
    })).await;

    assert_eq!(first_verify_response.status().as_u16(), 200);
    
    // Second verification with the SAME code - should fail
    let second_verify_response = app.post_verify_2fa(&serde_json::json!({
        "email": "test123@example.com",
        "loginAttemptId": login_attempt_id,
        "2FACode": actual_code  // Same code as above
    })).await;

    assert_eq!(second_verify_response.status().as_u16(), 401);
    
    app.clean_up().await;
}