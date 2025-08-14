use std::collections::{HashMap, HashSet};
use crate::domain::data_score::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

impl BannedTokenStore for HashsetBannedTokenStore {
    fn store_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        if self.banned_tokens.contains(token) {
            return Err(BannedTokenStoreError::TokenAlreadyBanned);
        }
        self.banned_tokens.insert(token.to_string());
        Ok(())
    }

    fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_token() {
        let mut store = HashsetBannedTokenStore::default();
        store.store_token("test_token").unwrap();
        assert!(store.is_token_banned("test_token").unwrap());
    }

    #[test]
    fn test_is_token_banned() {
        let mut store = HashsetBannedTokenStore::default();
        assert!(!store.is_token_banned("test_token").unwrap());
    }
}