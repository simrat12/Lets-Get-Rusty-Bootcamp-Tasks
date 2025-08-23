use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::EmailClient;
use crate::data_stores::data_store::{BannedTokenStoreType, TwoFACodeStore, UserStore};


// Type alias that depends on the UserStore trait using a trait object
pub type UserStoreType = Arc<RwLock<Box<dyn UserStore + Send + Sync>>>;
pub type TwoFACodeStoreType = Arc<RwLock<Box<dyn TwoFACodeStore + Send + Sync>>>;

pub type EmailClientType = Arc<RwLock<Box<dyn EmailClient + Send + Sync>>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: Arc<RwLock<BannedTokenStoreType>>,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub email_client: EmailClientType,
}

impl AppState {
    pub fn new(user_store: UserStoreType, banned_token_store: Arc<RwLock<BannedTokenStoreType>>, two_fa_code_store: TwoFACodeStoreType, email_client: EmailClientType) -> Self {
        Self { user_store, banned_token_store, two_fa_code_store, email_client }
    }
}