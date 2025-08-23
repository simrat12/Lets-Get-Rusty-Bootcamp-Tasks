use crate::domain::user::User;
use crate::domain::email::Email;
use crate::domain::password::Password;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use rand::Rng;
use crate::data_stores::redis_banned_token_store::RedisBannedTokenStore;

// ============================================================================
// TRAITS
// ============================================================================

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
    async fn remove_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError>;
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: &Email,
        login_attempt_id: &LoginAttemptId,
        code: &TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    TokenAlreadyBanned,
    TokenNotFound,
    UnexpectedError,
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

// ============================================================================
// ENUM IMPLEMENTATIONS
// ============================================================================

pub enum BannedTokenStoreType {
    Hashset(HashsetBannedTokenStore),
    Redis(RedisBannedTokenStore),
}

#[async_trait::async_trait]
impl BannedTokenStore for BannedTokenStoreType {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        match self {
            Self::Hashset(store) => store.add_token(token).await,
            Self::Redis(store) => store.add_token(token).await,
        }
    }
    
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        match self {
            Self::Hashset(store) => store.contains_token(token).await,
            Self::Redis(store) => store.contains_token(token).await,
        }
    }

    async fn remove_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        match self {
            Self::Hashset(store) => store.remove_token(token).await,
            Self::Redis(store) => store.remove_token(token).await,
        }
    }

    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        match self {
            Self::Hashset(store) => store.store_token(token).await,
            Self::Redis(store) => store.store_token(token).await,
        }
    }

    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        match self {
            Self::Hashset(store) => store.is_token_banned(token).await,
            Self::Redis(store) => store.is_token_banned(token).await,
        }
    }
}

// ============================================================================
// DOMAIN TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        match Uuid::parse_str(&id) {
            Ok(_) => Ok(LoginAttemptId(id)),
            Err(_) => Err(format!("Invalid UUID: {}", id)),
        }
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        match code.len() {
            6 => Ok(TwoFACode(code)),
            _ => Err(format!("Invalid 2FA code: {}", code)),
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::thread_rng().gen_range(100000..=999999);
        TwoFACode(code.to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ============================================================================
// CONCRETE IMPLEMENTATIONS
// ============================================================================

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        let email = user.email.clone();
        self.users.insert(email, user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users.get(email).cloned().ok_or(UserStoreError::UserNotFound)
    }
    
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password.as_ref() == password.as_ref() {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        if self.banned_tokens.contains(&token) {
            return Err(BannedTokenStoreError::TokenAlreadyBanned);
        }
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }

    async fn remove_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        if self.banned_tokens.remove(token) {
            Ok(())
        } else {
            Err(BannedTokenStoreError::TokenNotFound)
        }
    }

    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        if self.banned_tokens.contains(&token) {
            return Err(BannedTokenStoreError::TokenAlreadyBanned);
        }
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: &Email,
        login_attempt_id: &LoginAttemptId,
        code: &TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email.clone(), (login_attempt_id.clone(), code.clone()));
        Ok(())
    }
    
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }
    
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes.get(email)
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // HashmapUserStore tests
    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse("test@email.com".to_string()).unwrap(),
            password: Password::parse("password123".to_string()).unwrap(),
            requires_2fa: false,
        };
        assert_eq!(store.add_user(user).await, Ok(()));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse("test@gmail.com".to_string()).unwrap(),
            password: Password::parse("password123".to_string()).unwrap(),
            requires_2fa: false,
        };
        let _ = store.add_user(user).await;
        if let Ok(user) = store.get_user(&Email::parse("test@gmail.com".to_string()).unwrap()).await {
            assert_eq!(user.email, Email::parse("test@gmail.com".to_string()).unwrap());
            assert_eq!(user.password, Password::parse("password123".to_string()).unwrap());
            assert_eq!(user.requires_2fa, false);
        } else {
            panic!("User not found");
        }
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse("test@gmail.com".to_string()).unwrap(),
            password: Password::parse("password123".to_string()).unwrap(),
            requires_2fa: false,
        };

        let _ = store.add_user(user).await;
        assert_eq!(store.validate_user(&Email::parse("test@gmail.com".to_string()).unwrap(), &Password::parse("password123".to_string()).unwrap()).await, Ok(()));
    }

    // HashsetBannedTokenStore tests
    #[tokio::test]
    async fn test_store_token() {
        let mut store = HashsetBannedTokenStore::default();
        store.store_token("test_token".to_string()).await.unwrap();
        assert!(store.is_token_banned("test_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_is_token_banned() {
        let store = HashsetBannedTokenStore::default();
        assert!(!store.is_token_banned("test_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashsetBannedTokenStore::default();
        store.add_token("test_token".to_string()).await.unwrap();
        assert!(store.contains_token("test_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_remove_token() {
        let mut store = HashsetBannedTokenStore::default();
        store.add_token("test_token".to_string()).await.unwrap();
        store.remove_token("test_token").await.unwrap();
        assert!(!store.contains_token("test_token").await.unwrap());
    }

    // HashmapTwoFACodeStore tests
    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@email.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store.add_code(&email, &login_attempt_id, &code).await.unwrap();
        assert_eq!(store.get_code(&email).await.unwrap(), (login_attempt_id, code));
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@email.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store.add_code(&email, &login_attempt_id, &code).await.unwrap();
        store.remove_code(&email).await.unwrap();
        assert_eq!(store.get_code(&email).await.unwrap_err(), TwoFACodeStoreError::LoginAttemptIdNotFound);
    }

    // BannedTokenStoreType tests
    #[tokio::test]
    async fn test_banned_token_store_type_hashset() {
        let mut store = BannedTokenStoreType::Hashset(HashsetBannedTokenStore::default());
        store.add_token("test_token".to_string()).await.unwrap();
        assert!(store.contains_token("test_token").await.unwrap());
        store.remove_token("test_token").await.unwrap();
        assert!(!store.contains_token("test_token").await.unwrap());
    }
}
