use crate::helpers::{get_random_email, TestApp};

// #[tokio::test]
// async fn signup_returns_200() {
//     let app = TestApp::new().await;

//     let response = app.signup().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    // TODO: add more malformed input test cases
    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "invalid-email-format",
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.signup(test_case).await; // call `signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}