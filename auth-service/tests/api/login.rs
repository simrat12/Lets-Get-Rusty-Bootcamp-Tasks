use crate::helpers::{TestApp, get_random_email};
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

// #[tokio::test]
// async fn login_returns_200() {
//     let app = TestApp::new().await;

//     let response = app.login().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let response = app.login(&serde_json::json!({
        "email": "invalid_email",
        "password": "invalid_password"
    })).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    let app = TestApp::new().await;

    // Don't signup - try to login with non-existent user
    let response = app.login(&serde_json::json!({
        "email": "nonexistent@example.com",
        "password": "password123!"
    })).await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.     
    let app = TestApp::new().await;

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
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

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
}