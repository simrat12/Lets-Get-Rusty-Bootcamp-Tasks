use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::data_score::UserStore;
use crate::domain::data_score::BannedTokenStore;

// Type alias that depends on the UserStore trait using a trait object
pub type UserStoreType = Arc<RwLock<Box<dyn UserStore + Send + Sync>>>;
pub type BannedTokenStoreType = Arc<RwLock<Box<dyn BannedTokenStore + Send + Sync>>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: BannedTokenStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType, banned_token_store: BannedTokenStoreType) -> Self {
        Self { user_store, banned_token_store }
    }
}