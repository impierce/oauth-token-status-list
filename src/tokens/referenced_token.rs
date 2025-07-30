use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use url::Url;

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
    pub status: StatusClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

impl ReferencedTokenClaims {
    pub fn new(
        sub: Option<String>,
        iat: Option<i64>,
        exp: Option<i64>,
        ttl: Option<u64>,
        status: StatusClaim,
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
pub struct StatusClaim {
    #[serde(rename = "status_list")]
    pub referenced_status_list: ReferencedStatusList,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferencedStatusList {
    pub idx: i64,
    pub uri: Url,
}

impl Default for ReferencedStatusList {
    fn default() -> Self {
        ReferencedStatusList {
            idx: 0,
            uri: Url::parse("https://example.com/default").unwrap(),
        }
    }
}
