use crate::{
    error::OAuthTSLError,
    status_list::{StatusList, StatusType},
    tokens::{
        referenced_token::{ReferencedToken, ReferencedTokenClaims},
        status_list_token::{StatusListToken, StatusListTokenClaims, StatusListTyp},
    },
};
use flate2::read::GzDecoder;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use reqwest::{header, redirect::Policy, Client};
use std::io::Read;

/// The media types defined for status list tokens.
#[derive(Debug)]
pub enum StatusListTokenResponseType {
    Jwt,
    Cwt,
}

impl StatusListTokenResponseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusListTokenResponseType::Jwt => "application/statuslist+jwt",
            StatusListTokenResponseType::Cwt => "application/statuslist+cwt",
        }
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
    if header.typ != Some(StatusListTyp::Jwt.as_string()) {
        return Err(OAuthTSLError::InvalidHeaderTypeClaim(format!(
            "{:?}",
            header.typ
        )));
    }

    // Set up validation rules for the JWT.
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["status"]);
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data = decode::<ReferencedTokenClaims>(token_jwt, &decoding_key, &validation)?;

    let status_list_claim = token_data.claims.status.status_list_claim.clone();
    let now = chrono::Utc::now().timestamp();

    // Check the "issued at" (iat), "subject" (sub) and "expiration" (exp) claims.
    if let Some(iat) = token_data.claims.iat {
        if iat > now {
            return Err(OAuthTSLError::InvalidReferencedTokenClaims(format!(
                "{:?}",
                token_data
            )));
        }
    }

    if let Some(exp) = token_data.claims.exp {
        if exp < now {
            return Err(OAuthTSLError::ExpiredReferencedToken(format!(
                "{:?}",
                token_data
            )));
        }
    }

    if status_list_claim.uri.is_empty() {
        return Err(OAuthTSLError::InvalidReferencedTokenClaims(format!(
            "{:?}",
            token_data
        )));
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
    if header.typ != Some(StatusListTyp::Jwt.as_string()) {
        return Err(OAuthTSLError::InvalidHeaderTypeClaim(format!(
            "{:?}",
            header.typ
        )));
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
        || token_data.claims.iat > now
    {
        return Err(OAuthTSLError::InvalidStatusListTokenClaims(format!(
            "{:?}",
            token_data
        )));
    }

    if let Some(exp) = token_data.claims.exp {
        if exp < now {
            return Err(OAuthTSLError::InvalidStatusListTokenClaims(format!(
                "{:?}",
                token_data
            )));
        }
    }

    let status_list_token = StatusListToken {
        header: token_data.header,
        claims: token_data.claims,
    };

    Ok(status_list_token)
}

/// Check and return the status of the Referenced Token index, while validating both Status List Token and Referenced Token.
pub async fn check_referenced_token_index(
    referenced_token: &ReferencedToken,
    decoding_key: DecodingKey,
) -> Result<StatusType, OAuthTSLError> {
    // Get the status list from the Status Provider
    let uri = &referenced_token.claims.status.status_list_claim.uri;
    let index = referenced_token.claims.status.status_list_claim.idx;

    // TODO: currently the Accept Header is hardcoded to only accept JWT since this library only implements JWT.
    let status_list_gzip = fetch_status_list(uri, StatusListTokenResponseType::Jwt).await?;
    let status_list_jwt_string = decompress_gzip(&status_list_gzip)?;
    let status_list_jwt = decrypt_status_list_token(&status_list_jwt_string, decoding_key)?;

    if uri != &status_list_jwt.claims.sub {
        return Err(OAuthTSLError::InvalidStatusListTokenClaims(
            "`sub` claim (URI) mismatch between Status List Token and Referenced Token".to_string(),
        ));
    }

    let status_list: StatusList = status_list_jwt.claims.encoded_status_list.try_into()?;

    // Here is a good place to check the length of the status_list, but how to propogate a warning?
    // Issuers should provide "Herd Privacy" within status_lists so small lengths or even single statusses in one status_list is alarming.

    let status = status_list.get_index(index as usize)?;
    let status_type = StatusType::try_from(status)?;

    Ok(status_type)
}

/// Sends a status list request to the provided URI and returns the GZIP compressed JWT string as a Vec<u8>.
pub async fn fetch_status_list(
    uri: &str,
    accept_header: StatusListTokenResponseType,
) -> Result<Vec<u8>, OAuthTSLError> {
    // 3xx redirects should be followed, but infinite loops are caught after 5 redirects.
    let client = Client::builder()
        .redirect(Policy::limited(5)) // Allow up to 5 redirects
        .build()?;

    let res = client
        .get(uri)
        .header(header::ACCEPT, accept_header.as_str())
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(OAuthTSLError::UnexpectedError(format!(
            "Failed to fetch status list: {}",
            res.status()
        )));
    }

    let jwt_bytes = res.bytes().await?;
    let jwt_vec_u8 = jwt_bytes.to_vec();

    Ok(jwt_vec_u8)
}

// Helpers

pub fn decompress_gzip(data: &[u8]) -> Result<String, OAuthTSLError> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed_data = String::new();
    decoder.read_to_string(&mut decompressed_data)?;

    Ok(decompressed_data)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use reqwest::header::CONTENT_TYPE;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::{
        managers::{
            relying_party::{
                check_referenced_token_index, decompress_gzip, decrypt_referenced_token_jwt,
                decrypt_status_list_token, fetch_status_list, StatusListTokenResponseType,
            },
            status_provider::compress_gzip,
        },
        status_list::{EncodedStatusList, StatusList, StatusType},
        tokens::{
            referenced_token::{ReferencedToken, ReferencedTokenClaims, Status, StatusListClaim},
            status_list_token::{StatusListToken, StatusListTokenClaims, StatusListTyp},
        },
    };

    #[test]
    pub fn test_decrypt_referenced_token() {
        let status_list_claim = StatusListClaim {
            uri: "test".to_string(),
            idx: 123,
        };
        let status = Status { status_list_claim };

        let referenced_token = ReferencedToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some(StatusListTyp::Jwt.as_string()),
                ..Default::default()
            },
            claims: ReferencedTokenClaims {
                status,
                ..Default::default()
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
        status_list.set_index(4, 1).unwrap();
        let encoded_list: EncodedStatusList = status_list.try_into().unwrap();

        let status_list_token = StatusListToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some(StatusListTyp::Jwt.as_string()),
                ..Default::default()
            },
            claims: StatusListTokenClaims {
                sub: "Not empty".to_string(),
                iat: -1,
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

    #[tokio::test]
    pub async fn test_check_referenced_token() {
        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let decoding_key = DecodingKey::from_secret("secret".as_ref());

        // Create a new mock server, retrieve it's url
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        // Create Status List Token
        let mut status_list = StatusList::default();
        status_list
            .set_index(123, StatusType::INVALID as u8)
            .unwrap();
        let encoded_status_list = EncodedStatusList::try_from(status_list).unwrap();
        let claims =
            StatusListTokenClaims::new(server_url.clone(), -1, None, None, encoded_status_list);
        let status_list_token = StatusListToken::new(Algorithm::HS256, claims);
        let status_list_token_jwt = status_list_token.create_jwt(&encoding_key).unwrap();
        let compressed_jwt = compress_gzip(&status_list_token_jwt).unwrap();

        // Host the Status List Token.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/statuslist+jwt")
                    .set_body_bytes(compressed_jwt),
            )
            .mount(&mock_server)
            .await;

        // Create the Referenced Token
        let status_list_claim = StatusListClaim {
            uri: server_url,
            idx: 123,
        };
        let status = Status { status_list_claim };

        let referenced_token = ReferencedToken {
            header: Header {
                alg: Algorithm::HS256,
                ..Default::default()
            },
            claims: ReferencedTokenClaims {
                status,
                ..Default::default()
            },
        };

        let status_type = check_referenced_token_index(&referenced_token, decoding_key)
            .await
            .unwrap();

        assert_eq!(status_type, StatusType::INVALID);
    }

    #[tokio::test]
    pub async fn test_fetch_status_list() {
        let test_str = "test";
        let compressed = compress_gzip(test_str).unwrap();

        // Create a new mock server and retreive it's url.
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/statuslist+jwt")
                    .set_body_bytes(compressed),
            )
            .mount(&mock_server)
            .await;

        let response = fetch_status_list(&server_url, StatusListTokenResponseType::Jwt)
            .await
            .unwrap();

        let decompressed = decompress_gzip(&response).unwrap();

        assert_eq!(test_str, decompressed);
    }
}
