use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A running mock SCIM + OIDC server with pre-configured responses.
#[allow(dead_code)]
pub struct MockIdp {
    pub server: MockServer,
}

#[allow(dead_code)]
impl MockIdp {
    /// Start a mock server with a single test user and group.
    pub async fn start() -> Self {
        let server = MockServer::start().await;

        // SCIM: GET /Users?filter=userName eq "alice"
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
            .mount(&server)
            .await;

        // SCIM: GET /Users?filter=userName eq "disabled_bob"
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
            .mount(&server)
            .await;

        // SCIM: GET /Users?filter=userName eq "nonexistent"
        Mock::given(method("GET"))
            .and(path("/Users"))
            .and(query_param("filter", "userName eq \"nonexistent\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "Resources": []
            })))
            .mount(&server)
            .await;

        // SCIM: GET /Groups?filter=displayName eq "engineering"
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
            .mount(&server)
            .await;

        // SCIM: GET /Groups?filter=displayName eq "nonexistent"
        Mock::given(method("GET"))
            .and(path("/Groups"))
            .and(query_param("filter", "displayName eq \"nonexistent\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "Resources": []
            })))
            .mount(&server)
            .await;

        // SCIM: GET /Users?startIndex=1&count=100 (enumeration)
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
            .mount(&server)
            .await;

        // SCIM: GET /Groups?startIndex=1&count=100 (enumeration)
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
            .mount(&server)
            .await;

        // SCIM: GET /Users?count=0 (health check)
        Mock::given(method("GET"))
            .and(path("/Users"))
            .and(query_param("count", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 2,
                "Resources": []
            })))
            .mount(&server)
            .await;

        // OIDC: GET /.well-known/openid-configuration
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "device_authorization_endpoint": format!("{issuer}/device"),
                "jwks_uri": format!("{issuer}/jwks"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
            })))
            .mount(&server)
            .await;

        Self { server }
    }

    /// Mount device code flow mocks: POST /device returns a device code,
    /// POST /token returns authorization_pending once then succeeds.
    pub async fn mount_device_code_flow(&self) {
        // POST /device → returns device code
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "test-device-code-001",
                "user_code": "ABCD-1234",
                "verification_uri": format!("{}/activate", self.server.uri()),
                "verification_uri_complete": format!("{}/activate?code=ABCD-1234", self.server.uri()),
                "expires_in": 600,
                "interval": 0
            })))
            .mount(&self.server)
            .await;

        // POST /token → first call returns authorization_pending (fires once)
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "authorization_pending",
                "error_description": "The user has not yet completed authorization"
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&self.server)
            .await;

        // POST /token → second call succeeds (lower priority, fires after the first)
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-access-token-001",
                "id_token": "test-id-token-001",
                "token_type": "Bearer"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount device code flow mocks that always return expired_token.
    pub async fn mount_device_code_flow_expired(&self) {
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "test-device-code-expired",
                "user_code": "XXXX-9999",
                "verification_uri": format!("{}/activate", self.server.uri()),
                "expires_in": 600,
                "interval": 0
            })))
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "expired_token",
                "error_description": "The device code has expired"
            })))
            .mount(&self.server)
            .await;
    }

    pub fn base_url(&self) -> String {
        self.server.uri()
    }
}
