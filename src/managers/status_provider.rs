use super::relying_party::StatusListTokenResponseType;
use crate::error::OAuthTSLError;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

// Status Provider handler with dynamic path segment serving as the status list key
// This allows the same endpoint to serve multiple status lists based on the key provided in the path
async fn status_provider_handler(
    State(provider): State<Arc<StatusProvider>>,
    headers: HeaderMap,
    Path(status_list_key): Path<String>,
) -> Result<Response, OAuthTSLError> {
    let content_type = headers
        .get(header::ACCEPT)
        .and_then(|content_type_value| content_type_value.to_str().ok())
        .ok_or(OAuthTSLError::InvalidAcceptHeader)?;
    let token_type = StatusListTokenResponseType::try_from(content_type)
        .map_err(|_| OAuthTSLError::InvalidAcceptHeader)?;

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

    /// The HTTP response uses gzip Content-Encoding as defined in [RFC9110].
    pub async fn serve_status_list_token(
        &self,
        token_type: StatusListTokenResponseType,
        status_list_key: &str,
    ) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
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
    /// This route supports CORS for GET requests.
    pub fn create_route_with_dynamic_path(&self, route_str: &str) -> Router {
        let route = route_str.trim_end_matches('/').to_string() + "/{path}";

        let cors = CorsLayer::new()
            .allow_methods([Method::GET])
            .allow_origin(Any)
            .allow_headers(Any); // Allow custom headers if needed

        Router::new()
            .route(&route, get(status_provider_handler))
            .layer(cors)
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
