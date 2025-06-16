use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferencedToken {
    header: Header,
    claims: ReferencedTokenClaims,
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

    pub fn create_jwt(self, key: &EncodingKey) -> Result<String, String> {
        encode(&self.header, &self.claims, key).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ReferencedTokenClaims {
    pub status: Status,
    pub sub: String,
    pub iat: i64,
    pub exp: Option<i64>,
    pub ttl: Option<u64>,
}

impl ReferencedTokenClaims {
    pub fn new(sub: String, iat: i64, exp: Option<i64>, ttl: Option<u64>, status: Status) -> Self {
        Self {
            sub,
            iat,
            exp,
            ttl,
            status,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub status_list_ref: StatusListRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListRef {
    pub idx: i64,
    pub uri: String,
}
