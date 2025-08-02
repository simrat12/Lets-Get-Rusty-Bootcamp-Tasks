use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::data_score::UserStore;

// Type alias that depends on the UserStore trait using a trait object
pub type UserStoreType = Arc<RwLock<Box<dyn UserStore + Send + Sync>>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}