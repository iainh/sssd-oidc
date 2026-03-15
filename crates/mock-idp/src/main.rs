use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Standalone mock SCIM 2.0 + OIDC server for container-based E2E tests.
///
/// Listens on 0.0.0.0:9980 and provides:
/// - SCIM user/group endpoints (alice, disabled_bob, engineering)
/// - OIDC discovery + device code flow (auto-approves after one pending poll)
#[tokio::main]
async fn main() {
    let listener = std::net::TcpListener::bind("0.0.0.0:9980").expect("failed to bind :9980");
    let server = MockServer::builder().listener(listener).start().await;
    let base = server.uri();
    eprintln!("mock-idp listening on {base}");

    mount_scim_mocks(&server).await;
    mount_oidc_mocks(&server, &base).await;

    eprintln!("mock-idp ready");

    // Wait for SIGTERM/SIGINT
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    eprintln!("mock-idp shutting down");
}

async fn mount_scim_mocks(server: &MockServer) {
    // GET /Users?filter=userName eq "alice"
    Mock::given(method("GET"))
        .and(path("/Users"))
        .and(query_param("filter", "userName eq \"alice\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [{
                "id": "user-uuid-alice-001",
                "userName": "alice",
                "displayName": "Alice Smith",
                "active": true,
                "groups": [{
                    "value": "group-uuid-eng-001",
                    "display": "engineering"
                }]
            }]
        })))
        .mount(server)
        .await;

    // GET /Users?filter=userName eq "disabled_bob"
    Mock::given(method("GET"))
        .and(path("/Users"))
        .and(query_param("filter", "userName eq \"disabled_bob\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [{
                "id": "user-uuid-bob-002",
                "userName": "disabled_bob",
                "displayName": "Bob Disabled",
                "active": false,
                "groups": []
            }]
        })))
        .mount(server)
        .await;

    // GET /Users?filter=userName eq "<unknown>" → empty
    // (wiremock returns 404 for unmatched requests, which our code handles)

    // GET /Groups?filter=displayName eq "engineering"
    Mock::given(method("GET"))
        .and(path("/Groups"))
        .and(query_param("filter", "displayName eq \"engineering\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [{
                "id": "group-uuid-eng-001",
                "displayName": "engineering",
                "members": [{
                    "value": "user-uuid-alice-001",
                    "display": "alice"
                }]
            }]
        })))
        .mount(server)
        .await;

    // GET /Users?startIndex=1&count=100 (enumeration)
    Mock::given(method("GET"))
        .and(path("/Users"))
        .and(query_param("startIndex", "1"))
        .and(query_param("count", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "startIndex": 1,
            "itemsPerPage": 100,
            "Resources": [
                {
                    "id": "user-uuid-alice-001",
                    "userName": "alice",
                    "displayName": "Alice Smith",
                    "active": true,
                    "groups": [{"value": "group-uuid-eng-001", "display": "engineering"}]
                },
                {
                    "id": "user-uuid-bob-002",
                    "userName": "disabled_bob",
                    "displayName": "Bob Disabled",
                    "active": false,
                    "groups": []
                }
            ]
        })))
        .mount(server)
        .await;

    // GET /Groups?startIndex=1&count=100 (enumeration)
    Mock::given(method("GET"))
        .and(path("/Groups"))
        .and(query_param("startIndex", "1"))
        .and(query_param("count", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 100,
            "Resources": [{
                "id": "group-uuid-eng-001",
                "displayName": "engineering",
                "members": [{"value": "user-uuid-alice-001", "display": "alice"}]
            }]
        })))
        .mount(server)
        .await;

    // GET /Users?count=0 (health check)
    Mock::given(method("GET"))
        .and(path("/Users"))
        .and(query_param("count", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": []
        })))
        .mount(server)
        .await;

    // GET /Users/<id> (by ID)
    Mock::given(method("GET"))
        .and(path("/Users/user-uuid-alice-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "user-uuid-alice-001",
            "userName": "alice",
            "displayName": "Alice Smith",
            "active": true,
            "groups": [{"value": "group-uuid-eng-001", "display": "engineering"}]
        })))
        .mount(server)
        .await;

    // GET /Groups/<id> (by ID)
    Mock::given(method("GET"))
        .and(path("/Groups/group-uuid-eng-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "group-uuid-eng-001",
            "displayName": "engineering",
            "members": [{"value": "user-uuid-alice-001", "display": "alice"}]
        })))
        .mount(server)
        .await;
}

async fn mount_oidc_mocks(server: &MockServer, base: &str) {
    // OIDC Discovery
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "device_authorization_endpoint": format!("{base}/device"),
            "jwks_uri": format!("{base}/jwks"),
            "userinfo_endpoint": format!("{base}/userinfo"),
        })))
        .mount(server)
        .await;

    // POST /device → device code
    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "test-device-code-001",
            "user_code": "ABCD-1234",
            "verification_uri": format!("{base}/activate"),
            "verification_uri_complete": format!("{base}/activate?code=ABCD-1234"),
            "expires_in": 600,
            "interval": 1
        })))
        .mount(server)
        .await;

    // POST /token → first call returns pending, subsequent calls succeed.
    // wiremock serves higher-priority (later-mounted) mocks first for
    // up_to_n_times, so mount the pending response first.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "authorization_pending",
            "error_description": "The user has not yet completed authorization"
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-access-token-001",
            "id_token": "test-id-token-001",
            "token_type": "Bearer"
        })))
        .mount(server)
        .await;
}
