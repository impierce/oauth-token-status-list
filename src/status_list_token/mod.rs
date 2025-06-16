use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::status_list::StatusList;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListTokenClaims {
    pub sub: String,
    pub iat: i64,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub ttl: Option<u64>,
    pub status_list: StatusList,
}

impl std::default::Default for StatusListTokenClaims {
    fn default() -> Self {
        Self {
            sub: String::new(),
            iat: Utc::now().timestamp(),
            exp: None,
            ttl: None,
            status_list: StatusList::default(),
        }
    }
}

impl StatusListTokenClaims {
    pub fn new(
        sub: String,
        iat: i64,
        exp: Option<i64>,
        ttl: Option<u64>,
        status_list: StatusList,
    ) -> Self {
        Self {
            sub,
            iat,
            exp,
            ttl,
            status_list,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListToken {
    pub header: Header,
    pub claims: StatusListTokenClaims,
}

impl StatusListToken {
    pub fn new(alg: Algorithm, claims: StatusListTokenClaims) -> Self {
        Self {
            header: Header {
                alg,
                typ: Some("statuslist+jwt".to_string()),
                ..Default::default()
            },
            claims,
        }
    }

    pub fn create_jwt(self, key: &EncodingKey) -> Result<String, String> {
        encode(&self.header, &self.claims, key).map_err(|e| e.to_string())
    }
}

/// Default implementation uses ES256 for `alg `, current time for `iat`, empty string for `sub`, no `exp`, no `ttl`, and a default `StatusList`.
impl std::default::Default for StatusListToken {
    fn default() -> Self {
        Self {
            header: Header {
                alg: Algorithm::ES256,
                typ: Some("statuslist+jwt".to_string()),
                ..Default::default()
            },
            claims: StatusListTokenClaims::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    #[test]
    pub fn test_create_default_jwt() {
        // Using the HS256 algorithm for simplicity in this test.
        let status_list_token =
            StatusListToken::new(Algorithm::HS256, StatusListTokenClaims::default());

        let encoding_key = &EncodingKey::from_secret("secret".as_ref());

        let jwt = status_list_token.create_jwt(&encoding_key).unwrap();

        println!("JWT: {}", jwt);

        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let mut validation = Validation::new(Algorithm::HS256);

        validation.set_required_spec_claims(&["sub", "iat", "status_list"]);

        decode::<StatusListTokenClaims>(&jwt, &decoding_key, &validation)
            .expect("JWT validation failed");
    }
}
