use axum::{response::IntoResponse, http::StatusCode, Json, extract::State};
use crate::utils::auth::validate_token;
use crate::domain::error::AuthAPIError;
use crate::data_stores::data_store::BannedTokenStore;
use serde::Deserialize;
use crate::AppState;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

pub async fn verify_token(
    State(state): State<AppState>,
    Json(body): Json<VerifyTokenRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let banned_store = state.banned_token_store.read().await;
    match validate_token(&body.token, &*banned_store).await {
        Ok(_claims) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}