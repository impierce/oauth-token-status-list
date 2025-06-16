use reqwest::{header, redirect::Policy, Client};
use std::error::Error;

/// The media types defined for status list tokens.
#[derive(Debug)]
pub enum StatusListResponseType {
    Jwt,
    Cwt,
}

impl StatusListResponseType {
    fn as_str(&self) -> &'static str {
        match self {
            StatusListResponseType::Jwt => "application/statuslist+jwt",
            StatusListResponseType::Cwt => "application/statuslist+cwt",
        }
    }
}

/// Sends a status list request to the provided URI and returns the raw response body.
pub async fn fetch_status_list(
    uri: &str,
    accept_format: StatusListResponseType,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // 3xx redirects should be followed, but infinite loops are caught after 5 redirects.
    let client = Client::builder()
        .redirect(Policy::limited(5)) // Allow up to 5 redirects
        .build()?;

    let res = client
        .get(uri)
        .header(header::ACCEPT, accept_format.as_str())
        .send()
        .await?;

    // Handle redirect loop protection and successful responses
    match res.status() {
        status if status.is_success() => {
            let bytes = res.bytes().await?;
            Ok(bytes.to_vec())
        }
        status => Err(format!("Unexpected HTTP status code: {}", status).into()),
    }
}
