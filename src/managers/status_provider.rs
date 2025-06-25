use super::relying_party::StatusListTokenResponseType;
use crate::error::OAuthTSLError;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// status provider handler with optional path

async fn status_provider_handler(
    State(provider): State<Arc<StatusProvider>>,
    headers: HeaderMap,
    Path(status_list_key): Path<String>,
) -> Result<Response, OAuthTSLError> {
    println!("Received request for status list key: {}", status_list_key);

    let content_type = headers
        .get("content-type")
        .and_then(|content_type_value| content_type_value.to_str().ok())
        .ok_or(OAuthTSLError::InvalidContentType)?;
    let token_type = StatusListTokenResponseType::try_from(content_type)
        .map_err(|_| OAuthTSLError::InvalidContentType)?;

    Ok::<Response, OAuthTSLError>(
        provider
            .serve_status_list_token(token_type, &status_list_key)
            .await,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusProvider {
    /// The Status List Tokens are stored as the compressed and encoded JWT string with the uri to the endpoint as the key.
    pub status_list_tokens: HashMap<String, String>,
}

impl StatusProvider {
    pub fn get_status_list(&self, key: &str) -> Option<&String> {
        self.status_list_tokens.get(key)
    }

    pub async fn serve_status_list_token(
        &self,
        token_type: StatusListTokenResponseType,
        status_list_key: &str,
    ) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type",
            HeaderValue::from_static(token_type.as_str()),
        );

        match self.get_status_list(status_list_key) {
            Some(jwt_token) => (StatusCode::OK, headers, jwt_token.clone()).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                headers,
                "JWT-Token not found".to_string(),
            )
                .into_response(),
        }
    }

    /// Creates a route with a dynamic path segment at the end.
    /// This path segment is to be used to extract the status list key.
    /// This way one endpoint can serve multiple status lists.
    pub fn create_route_with_dynamic_path(&self, route_str: &str) -> Router {
        let route = route_str.trim_end_matches('/').to_string() + "/{path}";
        Router::new()
            .route(&route, get(status_provider_handler))
            .with_state(Arc::new(self.clone()))
    }
}

#[cfg(test)]
pub mod test {
    use crate::managers::{relying_party::*, status_provider::*};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::net::TcpListener; // adjust paths as needed

    #[tokio::test]
    pub async fn test_status_provider_handler() {
        let status_provider = StatusProvider {
            status_list_tokens: HashMap::from([("foo".to_string(), "test-jwt".to_string())]),
        };
        let status_provider = Arc::new(status_provider);

        // Set up route with handler that uses shared status_provider
        let path = "/status_lists";
        let app = status_provider.create_route_with_dynamic_path(&path);

        // Bind to available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); // OS assigns port
        let addr = listener.local_addr().unwrap();

        // Spawn server
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .expect("Server failed");
        });

        let uri = format!("http://{}{}/foo", addr, path);

        let res = fetch_status_list(&uri, StatusListTokenResponseType::Jwt)
            .await
            .expect("Failed to fetch status list");

        assert_eq!(res, "test-jwt");
    }
}
