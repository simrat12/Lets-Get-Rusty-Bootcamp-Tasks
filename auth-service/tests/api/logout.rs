use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;

use crate::helpers::TestApp;

// #[tokio::test]
// async fn logout_returns_200() {
//     let app = TestApp::new().await;

//     let response = app.logout().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 400);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    // add invalid cookie using the same URL as the test app
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse(&app.address).expect("Failed to parse URL"),
    );

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let email = "test@test.com";

    // First signup a user with 2FA disabled
    let signup_body = serde_json::json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    });

    app.signup(&signup_body).await;

    // Then login to generate JWT cookie
    let login_body = serde_json::json!({
        "email": email,
        "password": "password123"
    });

    let login_response = app.login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 200);

    // Verify that the JWT cookie was set and contains correct email
    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    
    assert!(!auth_cookie.value().is_empty());
    
    // Validate the JWT token contains the correct email using the helper function
    let verify_body = serde_json::json!({
        "token": auth_cookie.value()
    });
    let verify_response = app.post_verify_token(&verify_body).await;
    assert_eq!(verify_response.status().as_u16(), 200);

    // Now logout with the valid JWT cookie
    let logout_response = app.logout().await;
    assert_eq!(logout_response.status().as_u16(), 200);

    // Check if the token is banned
    let is_banned = app.is_token_banned(auth_cookie.value()).await;
    assert!(is_banned);

    // Verify that the token is no longer valid after logout
    let verify_after_logout_response = app.post_verify_token(&verify_body).await;
    assert_eq!(verify_after_logout_response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    // First signup a user with 2FA disabled
    let signup_body = serde_json::json!({
        "email": "test@test.com",
        "password": "password123",
        "requires2FA": false
    });

    app.signup(&signup_body).await;

    // Then login to generate JWT cookie
    let login_body = serde_json::json!({
        "email": "test@test.com",
        "password": "password123"
    });

    app.login(&login_body).await;

    // Now logout with the valid JWT cookie
    app.logout().await;

    // Now logout again
    let logout_response = app.logout().await;
    assert_eq!(logout_response.status().as_u16(), 400);
    
    app.clean_up().await;
}