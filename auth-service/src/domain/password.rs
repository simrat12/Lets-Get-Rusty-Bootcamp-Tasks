#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Password(String);

impl Password {
    pub fn parse(s: String) -> Result<Self, PasswordError> {
        if s.len() < 8 {
            return Err(PasswordError::TooShort);
        }
        Ok(Password(s))
    }
}


impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub enum PasswordError {
    TooShort,
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_password() {
        let password = Password::parse("password".to_string());
        assert!(password.is_ok());
        assert_eq!(password.unwrap().as_ref(), "password");
    }
}