use crate::managers::error::StatusHandlerError;
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
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "application/statuslist+jwt" => Ok(StatusListTokenResponseType::Jwt),
            "application/statuslist+cwt" => Ok(StatusListTokenResponseType::Cwt),
            _ => Err("Unsupported response type".to_string()),
        }
    }
}

/// Sends a status list request to the provided URI and returns the JWT string.
pub async fn fetch_status_list(
    uri: &str,
    accept_format: StatusListTokenResponseType,
) -> Result<String, StatusHandlerError> {
    // 3xx redirects should be followed, but infinite loops are caught after 5 redirects.
    let client = Client::builder()
        .redirect(Policy::limited(5)) // Allow up to 5 redirects
        .build()?;

    let res = client
        .get(uri)
        .header(header::CONTENT_TYPE, accept_format.as_str())
        .header("X-Status-List", "foo")
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(StatusHandlerError::UnexpectedError(format!(
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
        managers::relying_party::{fetch_status_list, StatusListTokenResponseType},
        status_list_token::{StatusListToken, StatusListTokenClaims},
    };

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
                    .insert_header(CONTENT_TYPE.as_str(), "application/statuslist+jwt")
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
