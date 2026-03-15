mod common;

use common::mock_idp::MockIdp;
use sssd_oidc::oidc::OidcClient;

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
