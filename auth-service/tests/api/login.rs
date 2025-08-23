use crate::helpers::{TestApp, get_random_email};
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse, routes::TwoFactorAuthResponse};

// #[tokio::test]
// async fn login_returns_200() {
//     let app = TestApp::new().await;

//     let response = app.login().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let response = app.login(&serde_json::json!({
        "email": "invalid_email",
        "password": "invalid_password"
    })).await;

    assert_eq!(response.status().as_u16(), 422);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    let mut app = TestApp::new().await;

    // Don't signup - try to login with non-existent user
    let response = app.login(&serde_json::json!({
        "email": "nonexistent@example.com",
        "password": "password123!"
    })).await;

    assert_eq!(response.status().as_u16(), 400);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.     
    let mut app = TestApp::new().await;

    // First signup a user - include the requires2FA field
    let signup_response = app.signup(&serde_json::json!({
        "email": "testPerson12@example.com",
        "password": "password123!",
        "requires2FA": false
    })).await;

    println!("Signup status: {}", signup_response.status().as_u16());
    let signup_body = signup_response.text().await.unwrap();
    println!("Signup body: {}", signup_body);

    // Then try to login with wrong password
    let response = app.login(&serde_json::json!({
        "email": "testPerson12@example.com",
        "password": "wrongpassword"
    })).await;

    // Log the response details
    let status = response.status().as_u16();
    println!("Response status: {}", status);
    let response_body = response.text().await.unwrap();
    println!("Response body: {}", response_body);

    assert_eq!(status, 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response_body = response.text().await.unwrap();
    println!("Response body: {}", response_body);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());

    // TODO: assert that `json_body.login_attempt_id` is stored inside `app.two_fa_code_store`
    let login_attempt_id = response_body.login_attempt_id;
    let email = auth_service::domain::email::Email::parse(random_email).unwrap();
    {
        let two_fa_code_store = app.app_state.two_fa_code_store.read().await;
        let stored_login_attempt_id = two_fa_code_store.get_code(&email).await.unwrap().0;
        assert_eq!(login_attempt_id, stored_login_attempt_id.as_ref());
    }
    
    app.clean_up().await;
}