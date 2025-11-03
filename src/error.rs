use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthTSLError {
    #[error("Error while base64 decoding: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Unable to create JWT: {0}")]
    CreateJwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Referenced token is expired: {0}")]
    ExpiredReferencedToken(i64),
    #[error("Status List Token is expired: {0}")]
    ExpiredStatusListToken(i64),
    #[error("Status List index, {0}, not found")]
    IndexNotFound(usize),
    #[error("Internal server error")]
    InternalError,
    #[error("Invalid Accept header passed in request")]
    InvalidAcceptHeader,
    #[error("Invalid content type passed in request header")]
    InvalidContentType,
    #[error("Invalid type claim (`typ`) in jwt header: {0:?}")]
    InvalidHeaderTypeClaim(Option<String>),
    #[error("When setting multiple values indices and values must have the same length")]
    InvalidIndicesValuesPair,
    #[error("Invalid referenced token issued at (iat) claim: {0}")]
    InvalidReferencedTokenIatClaim(i64),
    #[error("Invalid status list key passed in request header")]
    InvalidStatusListKey,
    #[error("Invalid status list token claims: {0}")]
    InvalidStatusListTokenClaims(String),
    #[error("Invalid status list token issued at (iat) claim: {0}")]
    InvalidStatusListTokenIatClaim(i64),
    #[error("Status size invalid: {0}")]
    InvalidStatusSize(usize),
    #[error("Status value invalid: {0}")]
    InvalidStatusType(u8),
    #[error("Error occured during standard I/O operation: {0}")]
    IOError(#[from] std::io::Error),
    #[error("An unexpected error occurred: {0}")]
    UnexpectedError(String),
}
