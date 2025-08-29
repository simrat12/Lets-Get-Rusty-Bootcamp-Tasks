#[derive(Debug)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    MalformedInput,
    IncorrectCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
}