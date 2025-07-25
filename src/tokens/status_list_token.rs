use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::{error::OAuthTSLError, status_list::EncodedStatusList};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListTokenClaims {
    pub sub: String,
    pub iat: i64,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub ttl: Option<u64>,
    #[serde(rename = "status_list")]
    pub encoded_status_list: EncodedStatusList,
}

impl std::default::Default for StatusListTokenClaims {
    fn default() -> Self {
        Self {
            sub: String::new(),
            iat: Utc::now().timestamp(),
            exp: None,
            ttl: None,
            encoded_status_list: EncodedStatusList::default(),
        }
    }
}

impl StatusListTokenClaims {
    pub fn new(
        sub: String,
        iat: i64,
        exp: Option<i64>,
        ttl: Option<u64>,
        status_list: EncodedStatusList,
    ) -> Self {
        Self {
            sub,
            iat,
            exp,
            ttl,
            encoded_status_list: status_list,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListToken {
    pub header: Header,
    pub claims: StatusListTokenClaims,
}

impl StatusListToken {
    pub fn new(alg: Algorithm, claims: StatusListTokenClaims) -> Self {
        Self {
            header: Header {
                alg,
                typ: Some(StatusListTyp::Jwt.as_string()),
                ..Default::default()
            },
            claims,
        }
    }

    pub fn create_jwt(&self, key: &EncodingKey) -> Result<String, OAuthTSLError> {
        Ok(encode(&self.header, &self.claims, key)?)
    }
}

/// Default implementation uses ES256 for `alg `, current time for `iat`, empty string for `sub`, no `exp`, no `ttl`, and a default `StatusList`.
impl std::default::Default for StatusListToken {
    fn default() -> Self {
        Self {
            header: Header {
                alg: Algorithm::ES256,
                typ: Some(StatusListTyp::Jwt.as_string()),
                ..Default::default()
            },
            claims: StatusListTokenClaims::default(),
        }
    }
}

pub enum StatusListTyp {
    Jwt,
    Cwt,
}

impl StatusListTyp {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusListTyp::Jwt => "statuslist+jwt",
            StatusListTyp::Cwt => "statuslist+cwt",
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            StatusListTyp::Jwt => "statuslist+jwt".to_string(),
            StatusListTyp::Cwt => "statuslist+cwt".to_string(),
        }
    }
}

impl TryFrom<&str> for StatusListTyp {
    type Error = OAuthTSLError;

    fn try_from(value: &str) -> Result<Self, OAuthTSLError> {
        match value {
            "statuslist+jwt" => Ok(StatusListTyp::Jwt),
            "statuslist+cwt" => Ok(StatusListTyp::Cwt),
            _ => Err(OAuthTSLError::InvalidContentType),
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

        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let mut validation = Validation::new(Algorithm::HS256);

        validation.set_required_spec_claims(&["sub", "iat", "status_list"]);

        decode::<StatusListTokenClaims>(&jwt, &decoding_key, &validation)
            .expect("JWT validation failed");
    }
}
