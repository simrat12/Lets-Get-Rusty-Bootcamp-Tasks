use crate::helpers::TestApp;

#[tokio::test]
async fn verify_token_returns_200() {
    let mut app = TestApp::new().await;

    // First, create a user and login to get a valid JWT
    let signup_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": false
    });
    app.signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": "test@example.com", 
        "password": "password123"
    });
    let login_response = app.login(&login_body).await;

    // Extract the JWT token from the login response cookie
    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == auth_service::utils::constants::JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let jwt_token = auth_cookie.value();

    // Now test verify_token with the valid JWT
    let verify_body = serde_json::json!({
        "token": jwt_token
    });

    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status().as_u16(), 200);
    
    app.clean_up().await;
}

#[tokio::test]
async fn verify_token_returns_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let response = app.post_verify_token(&serde_json::json!({})).await;

    assert_eq!(response.status().as_u16(), 422);
    
    app.clean_up().await;
}



#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    let response = app.post_verify_token(&serde_json::json!({
        "token": "invalid_token"
    })).await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}