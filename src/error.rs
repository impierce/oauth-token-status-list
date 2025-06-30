use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthTSLError {
    #[error("Invalid content type passed in request header")]
    InvalidContentType,
    #[error("Invalid Accept header passed in request")]
    InvalidAcceptHeader,
    #[error("Invalid status list key passed in request header")]
    InvalidStatusListKey,
    #[error("Invalid status list token claims: {0}")]
    InvalidStatusListTokenClaims(String),
    #[error("Internal server error")]
    InternalError,
    #[error("Request error (reqwest): {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("An unexpected error occurred: {0}")]
    UnexpectedError(String),
    #[error("Status List index, {0}, not found")]
    IndexNotFound(usize),
    #[error("Status value invalid: {0}")]
    InvalidStatusType(u8),
    #[error("Status size invalid: {0}")]
    InvalidStatusSize(usize),
    #[error("When setting multiple values indices and values must have the same length")]
    InvalidIndicesValuesPair,
    #[error("Error occured during standard I/O operation: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Error while base64 decoding: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Unable to create JWT: {0}")]
    CreateJwtError(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for OAuthTSLError {
    fn into_response(self) -> Response {
        match self {
            OAuthTSLError::InvalidContentType => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            OAuthTSLError::InvalidStatusListKey => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            OAuthTSLError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            OAuthTSLError::RequestError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            OAuthTSLError::UnexpectedError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
            // Not all errors will have nor need a specific status code and Response type.
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response(),
        }
    }
}
