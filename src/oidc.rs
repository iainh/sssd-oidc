use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("discovery document missing required field: {0}")]
    MissingField(String),
}

/// Endpoints parsed from the OIDC discovery document.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub issuer: String,
}

/// OIDC client for device authorization grant (RFC 8628).
///
/// The `http`, `client_id`, and `client_secret` fields are used by the
/// device code flow methods added in Feature 4.
#[allow(dead_code)]
pub struct OidcClient {
    http: reqwest::blocking::Client,
    endpoints: OidcEndpoints,
    client_id: String,
    client_secret: Option<String>,
}

/// Raw discovery document (only fields we need).
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
}

impl OidcClient {
    /// Discover endpoints from `{issuer_url}/.well-known/openid-configuration`
    /// and create an OIDC client.
    pub fn discover(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, OidcError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let http = reqwest::blocking::Client::new();
        let doc: DiscoveryDocument = http.get(&url).send()?.error_for_status()?.json()?;

        let issuer = doc
            .issuer
            .ok_or_else(|| OidcError::MissingField("issuer".into()))?;
        let token_endpoint = doc
            .token_endpoint
            .ok_or_else(|| OidcError::MissingField("token_endpoint".into()))?;
        let device_authorization_endpoint = doc
            .device_authorization_endpoint
            .ok_or_else(|| OidcError::MissingField("device_authorization_endpoint".into()))?;

        Ok(Self {
            http,
            endpoints: OidcEndpoints {
                device_authorization_endpoint,
                token_endpoint,
                issuer,
            },
            client_id: client_id.to_string(),
            client_secret: client_secret.map(String::from),
        })
    }

    /// Get the discovered endpoints.
    pub fn endpoints(&self) -> &OidcEndpoints {
        &self.endpoints
    }
}
