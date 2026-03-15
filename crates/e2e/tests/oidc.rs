mod common;

use common::mock_idp::MockIdp;
use sssd_oidc::oidc::{OidcClient, OidcError};

#[tokio::test(flavor = "multi_thread")]
async fn oidc_discovery_parses_endpoints() {
    let idp = MockIdp::start().await;
    let base_url = idp.base_url();

    let client = tokio::task::spawn_blocking(move || {
        OidcClient::discover(&base_url, "test-client", None).unwrap()
    })
    .await
    .unwrap();

    let endpoints = client.endpoints();
    assert!(endpoints.token_endpoint.contains("/token"));
    assert!(endpoints.device_authorization_endpoint.contains("/device"));
    assert!(!endpoints.issuer.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn device_code_flow_succeeds_after_pending() {
    let idp = MockIdp::start().await;
    idp.mount_device_code_flow().await;
    let base_url = idp.base_url();

    let result = tokio::task::spawn_blocking(move || {
        let client = OidcClient::discover(&base_url, "test-client", None).unwrap();
        let mut displayed_code = String::new();
        let mut displayed_uri = String::new();
        let token = client
            .authenticate_device_flow("openid", |code, uri| {
                displayed_code = code.to_string();
                displayed_uri = uri.to_string();
            })
            .unwrap();
        (token, displayed_code, displayed_uri)
    })
    .await
    .unwrap();

    assert_eq!(result.0.access_token, "test-access-token-001");
    assert_eq!(result.0.token_type, "Bearer");
    assert_eq!(result.1, "ABCD-1234");
    assert!(!result.2.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn device_code_flow_handles_expired_token() {
    let idp = MockIdp::start().await;
    idp.mount_device_code_flow_expired().await;
    let base_url = idp.base_url();

    let result = tokio::task::spawn_blocking(move || {
        let client = OidcClient::discover(&base_url, "test-client", None).unwrap();
        client.authenticate_device_flow("openid", |_code, _uri| {})
    })
    .await
    .unwrap();

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), OidcError::ExpiredToken));
}
