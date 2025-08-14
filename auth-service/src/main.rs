use auth_service::Application;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::banned_token_store::HashsetBannedTokenStore;
use auth_service::app_state::app_state::AppState;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::response::Html;
use auth_service::utils::constants::prod;

#[tokio::main]
async fn main() {

    let user_store = Arc::new(RwLock::new(Box::new(HashmapUserStore::default()) as Box<dyn auth_service::domain::data_score::UserStore + Send + Sync>));
    let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn auth_service::domain::data_score::BannedTokenStore + Send + Sync>));
    let app_state = AppState::new(user_store, banned_token_store);

    let app = Application::build(app_state, &prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn hello_handler() -> Html<&'static str> {
    // TODO: Update this to a custom message!
    Html("<h1>Hello, World! This is my first real attempt at Rust from scratch.</h1>")
}
