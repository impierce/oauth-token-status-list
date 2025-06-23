use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatusHandlerError {
    #[error("Invalid content type passed in request header")]
    InvalidContentType,
    #[error("Invalid status list key passed in request header")]
    InvalidStatusListKey,
    #[error("Internal server error")]
    InternalError,
    #[error("Request error (reqwest): {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("An unexpected error occurred: {0}")]
    UnexpectedError(String),
}

impl IntoResponse for StatusHandlerError {
    fn into_response(self) -> Response {
        match self {
            StatusHandlerError::InvalidContentType => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            StatusHandlerError::InvalidStatusListKey => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            StatusHandlerError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            StatusHandlerError::RequestError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            StatusHandlerError::UnexpectedError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}
