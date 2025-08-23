use crate::domain::email::Email;
use crate::domain::password::Password;

#[derive(Clone)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        Self { email, password, requires_2fa }
    }
}