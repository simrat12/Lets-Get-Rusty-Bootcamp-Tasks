use crate::domain::user::User;
use std::collections::HashMap;
use crate::domain::data_score::{UserStore, UserStoreError};
use crate::domain::email::Email;
use crate::domain::password::Password;

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        let email = user.email.clone();
        self.users.insert(email, user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }
    
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password == *password {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

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
}