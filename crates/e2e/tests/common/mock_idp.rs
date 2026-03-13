use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A running mock SCIM + OIDC server with pre-configured responses.
pub struct MockIdp {
    pub server: MockServer,
}

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

    pub fn base_url(&self) -> String {
        self.server.uri()
    }
}
