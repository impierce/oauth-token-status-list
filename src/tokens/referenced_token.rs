use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::error::OAuthTSLError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferencedToken {
    pub header: Header,
    pub claims: ReferencedTokenClaims,
}

impl ReferencedToken {
    pub fn new(alg: Algorithm, claims: ReferencedTokenClaims) -> Self {
        Self {
            header: Header {
                alg,
                ..Default::default()
            },
            claims,
        }
    }

    pub fn create_jwt(self, key: &EncodingKey) -> Result<String, OAuthTSLError> {
        Ok(encode(&self.header, &self.claims, key)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]

pub struct ReferencedTokenClaims {
    pub status: Status,
    pub sub: Option<String>,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub ttl: Option<u64>,
}

impl ReferencedTokenClaims {
    pub fn new(
        sub: Option<String>,
        iat: Option<i64>,
        exp: Option<i64>,
        ttl: Option<u64>,
        status: Status,
    ) -> Self {
        Self {
            sub,
            iat,
            exp,
            ttl,
            status,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Status {
    pub status_list_claim: StatusListClaim,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct StatusListClaim {
    pub idx: i64,
    pub uri: String,
}
