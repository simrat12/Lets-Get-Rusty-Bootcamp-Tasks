use std::collections::HashMap;

use crate::domain::{
    data_score::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}