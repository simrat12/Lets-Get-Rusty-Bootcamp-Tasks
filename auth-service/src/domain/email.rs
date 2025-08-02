#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Email {
    pub fn parse(s: String) -> Result<Self, EmailError> {
        if s.is_empty() || !s.contains('@') {
            return Err(EmailError::Invalid);
        }
        Ok(Email(s))
    }
}

#[derive(Debug)]
pub enum EmailError {
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        let email = Email::parse("test@example.com".to_string());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), "test@example.com");
    }

    #[test]
    fn test_empty_email() {
        let email = Email::parse("".to_string());
        assert!(email.is_err());
        assert!(matches!(email.unwrap_err(), EmailError::Invalid));
    }

    #[test]
    fn test_missing_at_symbol() {
        let email = Email::parse("testexample.com".to_string());
        assert!(email.is_err());
        assert!(matches!(email.unwrap_err(), EmailError::Invalid));
    }

    #[test]
    fn test_display_trait() {
        let email = Email::parse("test@example.com".to_string()).unwrap();
        assert_eq!(email.as_ref(), "test@example.com");
    }
} 