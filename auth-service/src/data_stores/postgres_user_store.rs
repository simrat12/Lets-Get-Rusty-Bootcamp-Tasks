use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::data_stores::data_store::{UserStore, UserStoreError};
use crate::domain::{email::Email, password::Password, user::User};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(&user.password.as_ref()).await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        
        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                UserStoreError::UserAlreadyExists
            } else {
                UserStoreError::UnexpectedError
            }
        })?;
        
        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user_row = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::UserNotFound)?;

        let user = User::new(
            Email::parse(user_row.email).map_err(|_| UserStoreError::UnexpectedError)?,
            Password::parse(user_row.password_hash).map_err(|_| UserStoreError::UnexpectedError)?,
            user_row.requires_2fa,
        );

        Ok(user)
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        
        verify_password_hash(&user.password.as_ref(), password.as_ref()).await
            .map_err(|_| UserStoreError::InvalidCredentials)?;
        
        Ok(())
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let expected_password_hash: PasswordHash<'_> = PasswordHash::new(expected_password_hash)?;
    
    // Clone the strings to own them for the closure
    let expected_password_hash = expected_password_hash.to_string();
    let password_candidate = password_candidate.to_string();

    tokio::task::spawn_blocking(move || {
        let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&expected_password_hash)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        
        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    )
    .hash_password(password.as_bytes(), &salt)
    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
    .to_string();

    Ok(password_hash)
}