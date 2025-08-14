use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie::Cookie};

use crate::{
    domain::error::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    AppState,
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Get cookie
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // Validate token
    {
        let banned_store = state.banned_token_store.read().await;
        if let Err(_) = validate_token(&token, &**banned_store).await {
            return (jar, Err(AuthAPIError::InvalidToken));
        }
    }

    // Ban the token by storing it in the banned token store
    {
        let mut banned_store = state.banned_token_store.write().await;
        if let Err(_) = banned_store.store_token(&token) {
            // If token is already banned, that's fine - we can still proceed
        }
    }

    // Remove the cookie by creating a removal cookie
    let removal_cookie = Cookie::build((JWT_COOKIE_NAME, ""))
        .path("/")
        .removal()
        .build();

    (jar.add(removal_cookie), Ok(StatusCode::OK))
}