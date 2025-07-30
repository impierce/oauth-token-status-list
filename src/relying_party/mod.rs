use crate::{
    error::OAuthTSLError,
    status_list::StatusList,
    tokens::{
        referenced_token::{ReferencedToken, ReferencedTokenClaims},
        status_list_token::{StatusListToken, StatusListTokenClaims, StatusListTyp},
    },
};
use flate2::read::GzDecoder;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{fmt, io::Read};

/// The media types defined for status list tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StatusListTokenResponseType {
    #[serde(rename = "application/statuslist+jwt")]
    Jwt,
    #[serde(rename = "application/statuslist+cwt")]
    Cwt,
}

impl From<StatusListTyp> for StatusListTokenResponseType {
    fn from(value: StatusListTyp) -> Self {
        match value {
            StatusListTyp::Jwt => StatusListTokenResponseType::Jwt,
            StatusListTyp::Cwt => StatusListTokenResponseType::Cwt,
        }
    }
}

impl fmt::Display for StatusListTokenResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            StatusListTokenResponseType::Jwt => "application/statuslist+jwt",
            StatusListTokenResponseType::Cwt => "application/statuslist+cwt",
        };
        write!(f, "{s}")
    }
}

impl TryFrom<&str> for StatusListTokenResponseType {
    type Error = OAuthTSLError;

    fn try_from(value: &str) -> Result<Self, OAuthTSLError> {
        match value {
            "application/statuslist+jwt" => Ok(StatusListTokenResponseType::Jwt),
            "application/statuslist+cwt" => Ok(StatusListTokenResponseType::Cwt),
            _ => Err(OAuthTSLError::InvalidContentType),
        }
    }
}

/// Decrypt and validate a referenced token jwt
pub fn decrypt_referenced_token_jwt(
    token_jwt: &str,
    decoding_key: DecodingKey,
) -> Result<ReferencedToken, OAuthTSLError> {
    let header = decode_header(token_jwt)?;
    if header.typ != Some(StatusListTyp::Jwt.to_string()) {
        return Err(OAuthTSLError::InvalidHeaderTypeClaim(header.typ));
    }

    // Set up validation rules for the JWT.
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["status"]);
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data = decode::<ReferencedTokenClaims>(token_jwt, &decoding_key, &validation)?;

    let now = chrono::Utc::now().timestamp();

    // Check the "issued at" (iat), "subject" (sub) and "expiration" (exp) claims.
    if let Some(iat) = token_data.claims.iat {
        if iat > now {
            return Err(OAuthTSLError::InvalidReferencedTokenIatClaim(iat));
        }
    }

    if let Some(exp) = token_data.claims.exp {
        if exp < now {
            return Err(OAuthTSLError::ExpiredReferencedToken(exp));
        }
    }

    let referenced_token = ReferencedToken {
        header: token_data.header,
        claims: token_data.claims,
    };

    Ok(referenced_token)
}

/// Decrypt and validate the status list token JWT and return the Status List Token.
pub fn decrypt_status_list_token(
    status_list_jwt: &str,
    decoding_key: DecodingKey,
) -> Result<StatusListToken, OAuthTSLError> {
    let header = decode_header(status_list_jwt)?;
    if header.typ != Some(StatusListTyp::Jwt.to_string()) {
        return Err(OAuthTSLError::InvalidHeaderTypeClaim(header.typ));
    }

    // Set up validation rules for the JWT.
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["sub", "iat", "status_list"]);
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data = decode::<StatusListTokenClaims>(status_list_jwt, &decoding_key, &validation)?;

    let now = chrono::Utc::now().timestamp();

    if token_data.claims.sub.is_empty()
        || token_data.claims.encoded_status_list.status_list.is_empty()
    {
        return Err(OAuthTSLError::InvalidStatusListTokenClaims(format!(
            "{:?}",
            token_data.claims
        )));
    }

    if token_data.claims.iat > now {
        return Err(OAuthTSLError::InvalidStatusListTokenIatClaim(
            token_data.claims.iat,
        ));
    }

    if let Some(exp) = token_data.claims.exp {
        if exp < now {
            return Err(OAuthTSLError::ExpiredStatusListToken(exp));
        }
    }

    let status_list_token = StatusListToken {
        header: token_data.header,
        claims: token_data.claims,
    };

    Ok(status_list_token)
}

pub fn decompress_gzip(data: &[u8]) -> Result<String, OAuthTSLError> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed_data = String::new();
    decoder.read_to_string(&mut decompressed_data)?;

    Ok(decompressed_data)
}

/// Checks the status of a given index in the status list response from the status provider.
/// Steps:
/// 1. Decompress the gzip response bytes into the JWT string.
/// 2. Decrypt the status list token JWT using the given decoding key.
/// 3. Convert the decoded JWT into a `StatusList` object.
/// 4. Retrieve the status at the specified index from the `StatusList`.
/// 5. Returns the status as a `u8`.
pub fn check_status_in_status_list_response(
    response_bytes: &[u8],
    index: usize,
    decoding_key: DecodingKey,
) -> Result<u8, OAuthTSLError> {
    let jwt_status_list_token = decompress_gzip(response_bytes)?;
    let decoded_jwt = decrypt_status_list_token(&jwt_status_list_token, decoding_key)?;
    let status_list = StatusList::try_from(decoded_jwt.claims.encoded_status_list)?;

    let status = status_list.get_status(index)?;

    Ok(status)
}

/// Checks the status of a given index in the status list token JWT string.
/// Steps:
/// 1. Decrypt the status list token JWT using the given decoding key.
/// 2. Convert the decoded JWT into a `StatusList` object.
/// 3. Retrieve the status at the specified index from the `StatusList`.
/// 4. Returns the status as a `u8`.
pub fn check_status_in_status_list_token_jwt(
    status_list_jwt: &str,
    index: usize,
    decoding_key: DecodingKey,
) -> Result<u8, OAuthTSLError> {
    let decoded_jwt = decrypt_status_list_token(status_list_jwt, decoding_key)?;
    let status_list = StatusList::try_from(decoded_jwt.claims.encoded_status_list)?;

    let status = status_list.get_status(index)?;

    Ok(status)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use url::Url;

    use crate::{
        relying_party::{decrypt_referenced_token_jwt, decrypt_status_list_token},
        status_list::{EncodedStatusList, StatusList},
        tokens::{
            referenced_token::{
                ReferencedStatusList, ReferencedToken, ReferencedTokenClaims, StatusClaim,
            },
            status_list_token::{StatusListToken, StatusListTokenClaims, StatusListTyp},
        },
    };

    #[test]
    pub fn test_decrypt_referenced_token() {
        let status_list_claim = ReferencedStatusList {
            idx: 123,
            uri: Url::parse("https://example.com/status/123").unwrap(),
        };
        let status = StatusClaim {
            referenced_status_list: status_list_claim,
        };

        let referenced_token = ReferencedToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some(StatusListTyp::Jwt.to_string()),
                ..Default::default()
            },
            claims: ReferencedTokenClaims {
                status,
                sub: None,
                iat: None,
                exp: None,
                ttl: None,
            },
        };

        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let jwt = referenced_token.clone().create_jwt(&encoding_key).unwrap();

        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let decrypted_referenced_token = decrypt_referenced_token_jwt(&jwt, decoding_key).unwrap();

        assert_eq!(referenced_token, decrypted_referenced_token);
    }

    #[test]
    pub fn test_decrypt_status_list_token() {
        let mut status_list = StatusList::default();
        status_list.set_status(4, 1).unwrap();
        let encoded_list: EncodedStatusList = status_list.try_into().unwrap();

        let status_list_token = StatusListToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some(StatusListTyp::Jwt.to_string()),
                ..Default::default()
            },
            claims: StatusListTokenClaims {
                sub: "Not empty".to_string(),
                iat: 1,
                exp: None,
                ttl: None,
                encoded_status_list: encoded_list,
            },
        };

        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let jwt = status_list_token.create_jwt(&encoding_key).unwrap();

        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let decrypted_status_list_token = decrypt_status_list_token(&jwt, decoding_key).unwrap();

        assert_eq!(status_list_token, decrypted_status_list_token);
    }
}
