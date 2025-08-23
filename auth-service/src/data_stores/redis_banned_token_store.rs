use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    data_stores::data_store::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);
        let mut conn = self.conn.write().await;
        conn.set_ex::<_, _, ()>(key, "true", TOKEN_TTL_SECONDS as u64).map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);
        let mut conn = self.conn.write().await;
        let exists: i32 = conn.exists(key).map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        Ok(exists == 1)
    }

    async fn remove_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        let key = get_key(token);
        let mut conn = self.conn.write().await;
        let deleted: i32 = conn.del(key).map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        if deleted == 0 {
            Err(BannedTokenStoreError::TokenNotFound)
        } else {
            Ok(())
        }
    }

    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.add_token(token).await
    }

    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        self.contains_token(token).await
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}