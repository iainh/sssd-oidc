mod common;

use common::mock_idp::MockIdp;
use sssd_oidc::oidc::{OidcClient, OidcError};

#[tokio::test(flavor = "multi_thread")]
async fn oidc_discovery_parses_endpoints() {
    let idp = MockIdp::start().await;
    let base_url = idp.base_url();

    let client = tokio::task::spawn_blocking(move || {
        OidcClient::discover(&base_url, "test-client-id", None).unwrap()
    })
    .await
    .unwrap();

    let endpoints = client.endpoints();
    assert!(endpoints.token_endpoint.contains("/token"));
    assert!(endpoints.device_authorization_endpoint.contains("/device"));
    assert!(endpoints.jwks_uri.contains("/jwks"));
    assert!(!endpoints.issuer.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn device_code_flow_succeeds_after_pending() {
    let idp = MockIdp::start().await;
    idp.mount_device_code_flow("test-subject").await;
    let base_url = idp.base_url();

    let (access_token, token_type, displayed_code, displayed_uri, sub) =
        tokio::task::spawn_blocking(move || {
            let client = OidcClient::discover(&base_url, "test-client-id", None).unwrap();
            let mut displayed_code = String::new();
            let mut displayed_uri = String::new();
            let token = client
                .authenticate_device_flow("openid", |code, uri| {
                    displayed_code = code.to_string();
                    displayed_uri = uri.to_string();
                })
                .unwrap();

            // Validate the ID token's signature, expiry, issuer, and audience
            let claims = client
                .validate_id_token(token.id_token.as_deref().unwrap())
                .unwrap();

            (
                token.access_token,
                token.token_type,
                displayed_code,
                displayed_uri,
                claims.sub,
            )
        })
        .await
        .unwrap();

    assert_eq!(access_token, "test-access-token-001");
    assert_eq!(token_type, "Bearer");
    assert_eq!(displayed_code, "ABCD-1234");
    assert!(!displayed_uri.is_empty());
    assert_eq!(sub, "test-subject");
}

#[tokio::test(flavor = "multi_thread")]
async fn device_code_flow_handles_expired_token() {
    let idp = MockIdp::start().await;
    idp.mount_device_code_flow_expired().await;
    let base_url = idp.base_url();

    let result = tokio::task::spawn_blocking(move || {
        let client = OidcClient::discover(&base_url, "test-client-id", None).unwrap();
        client.authenticate_device_flow("openid", |_code, _uri| {})
    })
    .await
    .unwrap();

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), OidcError::ExpiredToken));
}

#[tokio::test(flavor = "multi_thread")]
async fn validate_id_token_verifies_signature_and_claims() {
    let idp = MockIdp::start().await;
    idp.mount_device_code_flow("user-uuid-alice-001").await;
    let base_url = idp.base_url();

    let claims = tokio::task::spawn_blocking(move || {
        let client = OidcClient::discover(&base_url, "test-client-id", None).unwrap();
        let token = client
            .authenticate_device_flow("openid", |_, _| {})
            .unwrap();

        client
            .validate_id_token(token.id_token.as_deref().unwrap())
            .unwrap()
    })
    .await
    .unwrap();

    assert_eq!(claims.sub, "user-uuid-alice-001");
    assert!(claims.iss.starts_with("http://"));
    assert!(claims.exp > 0);
}
