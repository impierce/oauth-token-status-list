use crate::{
    error::OAuthTSLError,
    status_list::StatusType,
    tokens::{
        referenced_token::{ReferencedToken, ReferencedTokenClaims},
        status_list_token::{StatusListToken, StatusListTokenClaims},
    },
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use reqwest::{header, redirect::Policy, Client};

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
pub fn decrypt_referenced_token(
    token_jwt: &str,
    decoding_key: DecodingKey,
) -> Result<ReferencedToken, OAuthTSLError> {
    let header = decode_header(token_jwt)?;
    if header.typ != Some("statuslist+jwt".to_string()) {
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
    if header.typ != Some("statuslist+jwt".to_string()) {
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
        || token_data.claims.status_list.status_list.is_empty()
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
    let content_type = StatusListTokenResponseType::try_from(
        referenced_token
            .header
            .cty
            .clone()
            .ok_or(OAuthTSLError::InvalidContentType)?
            .as_str(),
    )?;

    // Get the status list from the Status Provider
    let uri = &referenced_token.claims.status.status_list_claim.uri;
    let index = referenced_token.claims.status.status_list_claim.idx;
    let status_list_token = fetch_status_list(uri, content_type).await?;
    let status_list_jwt = decrypt_status_list_token(&status_list_token, decoding_key)?;

    if uri != &status_list_jwt.claims.sub {
        return Err(OAuthTSLError::InvalidStatusListTokenClaims(
            "`sub` claim (URI) mismatch between Status List Token and Referenced Token".to_string(),
        ));
    }

    let status = status_list_jwt
        .claims
        .status_list
        .get_index(index as usize)?;
    let status_type = StatusType::try_from(status)?;

    Ok(status_type)
}

/// Sends a status list request to the provided URI and returns the JWT string.
pub async fn fetch_status_list(
    uri: &str,
    accept_header: StatusListTokenResponseType,
) -> Result<String, OAuthTSLError> {
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

    let jwt_string = res.text().await?;

    Ok(jwt_string)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use reqwest::header::CONTENT_TYPE;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::{
        managers::relying_party::{
            decrypt_status_list_token, fetch_status_list, StatusListTokenResponseType,
        },
        status_list::StatusList,
        tokens::status_list_token::{StatusListToken, StatusListTokenClaims},
    };

    #[test]
    pub fn test_decrypt_status_list_token() {
        // Create a new status list token with default values.
        let mut status_list = StatusList::default();
        status_list.set_index(4, 1).unwrap();

        let status_list_token = StatusListToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some("statuslist+jwt".to_string()),
                ..Default::default()
            },
            claims: StatusListTokenClaims {
                sub: "Valid".to_string(),
                iat: -1,
                exp: None,
                ttl: None,
                status_list,
            },
        };

        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let jwt = status_list_token.create_jwt(&encoding_key).unwrap();

        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let decrypted_status_list_token = decrypt_status_list_token(&jwt, decoding_key).unwrap();

        assert_eq!(status_list_token, decrypted_status_list_token);
    }

    #[tokio::test]
    pub async fn test_fetch_status_list() {
        // Create a new mock server and retreive it's url.
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let key = EncodingKey::from_secret("secret".as_ref());
        let decode_key = DecodingKey::from_secret("secret".as_ref());

        // Create the status list JWT as a string.
        let status_list_jwt = StatusListToken {
            header: Header {
                alg: Algorithm::HS256,
                typ: Some("statuslist+jwt".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
        .create_jwt(&key)
        .unwrap();

        // Create a new `request_uri` endpoint on the mock server and load it with the Status List JWT.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/statuslist+jwt")
                    .set_body_string(status_list_jwt),
            )
            .mount(&mock_server)
            .await;

        let response = fetch_status_list(&server_url, StatusListTokenResponseType::Jwt)
            .await
            .unwrap();

        // Set validation rules for the JWT.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["sub", "iat", "status_list"]);

        let jwt = decode::<StatusListTokenClaims>(&response, &decode_key, &validation);

        assert!(jwt.is_ok(), "JWT validation failed: {:?}", jwt.err());
    }
}
