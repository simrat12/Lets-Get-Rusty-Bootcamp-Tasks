use auth_service::Application;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::banned_token_store::HashsetBannedTokenStore;
use auth_service::services::hashmap_two_fa_code_store::HashmapTwoFACodeStore;
use auth_service::app_state::app_state::AppState;
use auth_service::services::mock_email_client::MockEmailClient;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::response::Html;
use auth_service::utils::constants::prod;

#[tokio::main]
async fn main() {

    let user_store = Arc::new(RwLock::new(Box::new(HashmapUserStore::default()) as Box<dyn auth_service::domain::data_score::UserStore + Send + Sync>));
    let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn auth_service::domain::data_score::BannedTokenStore + Send + Sync>));
    let two_fa_code_store = Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::default()) as Box<dyn auth_service::domain::data_score::TwoFACodeStore + Send + Sync>));
    let email_client = Arc::new(RwLock::new(Box::new(MockEmailClient::default()) as Box<dyn auth_service::domain::EmailClient + Send + Sync>));
    let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);

    let app = Application::build(app_state, &prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn hello_handler() -> Html<&'static str> {
    // TODO: Update this to a custom message!
    Html("<h1>Hello, World! This is my first real attempt at Rust from scratch.</h1>")
}
