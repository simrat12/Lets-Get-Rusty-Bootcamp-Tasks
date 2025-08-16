use auth_service::Application;
use uuid::Uuid;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::banned_token_store::HashsetBannedTokenStore;
use auth_service::services::hashmap_two_fa_code_store::HashmapTwoFACodeStore;
use auth_service::services::mock_email_client::MockEmailClient;
use auth_service::app_state::app_state::AppState;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::cookie::Jar;
use auth_service::utils::constants::test;

// Define Body type for the generic parameter
type Body = serde_json::Value;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub app_state: AppState, // Add this field
}

impl TestApp {
    pub async fn new() -> Self {
        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        let user_store = Arc::new(RwLock::new(Box::new(HashmapUserStore::default()) as Box<dyn auth_service::domain::data_score::UserStore + Send + Sync>));
        let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn auth_service::domain::data_score::BannedTokenStore + Send + Sync>));
        let two_fa_code_store = Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::default()) as Box<dyn auth_service::domain::data_score::TwoFACodeStore + Send + Sync>));
        let email_client = Arc::new(RwLock::new(Box::new(MockEmailClient::default()) as Box<dyn auth_service::domain::EmailClient + Send + Sync>));
        let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);

        let app = Application::build(app_state.clone(), &test::APP_ADDRESS) // Clone the app_state
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            cookie_jar,
            http_client,
            app_state, // Store the app_state
        }
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }


    pub async fn verify_token(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // Add a method to check if a token is banned
    pub async fn is_token_banned(&self, token: &str) -> bool {
        let banned_token_store = self.app_state.banned_token_store.read().await;
        banned_token_store.is_token_banned(token).unwrap_or(false) // Remove .await and add unwrap_or(false)
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
