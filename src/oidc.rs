use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("discovery document missing required field: {0}")]
    MissingField(String),
    #[error("authorization pending — user has not yet completed browser auth")]
    AuthorizationPending,
    #[error("polling too fast — increase interval")]
    SlowDown,
    #[error("device code has expired")]
    ExpiredToken,
    #[error("token request denied: {0}")]
    TokenError(String),
}

/// Endpoints parsed from the OIDC discovery document.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub issuer: String,
}

/// Response from the device authorization endpoint (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Successful token response.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub token_type: String,
}

/// Error response from the token endpoint during device code polling.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
}

/// OIDC client for device authorization grant (RFC 8628).
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

    /// Step 1: Request a device code from the device authorization endpoint.
    /// POST to device_authorization_endpoint with client_id + scope.
    pub fn request_device_code(&self, scope: &str) -> Result<DeviceAuthResponse, OidcError> {
        let mut form = vec![("client_id", self.client_id.as_str()), ("scope", scope)];
        if let Some(ref secret) = self.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let resp: DeviceAuthResponse = self
            .http
            .post(&self.endpoints.device_authorization_endpoint)
            .form(&form)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(resp)
    }

    /// Step 2: Poll for token until user completes browser auth.
    /// POST to token_endpoint with grant_type=urn:ietf:params:oauth:grant-type:device_code.
    ///
    /// Returns `Ok(TokenResponse)` on success.
    /// Returns `Err(OidcError::AuthorizationPending)` while waiting.
    /// Returns `Err(OidcError::SlowDown)` if polling too fast.
    /// Returns `Err(OidcError::ExpiredToken)` if the code expired.
    pub fn poll_for_token(&self, device_code: &str) -> Result<TokenResponse, OidcError> {
        let mut form = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ];
        if let Some(ref secret) = self.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let response = self
            .http
            .post(&self.endpoints.token_endpoint)
            .form(&form)
            .send()?;

        if response.status().is_success() {
            let token: TokenResponse = response.json()?;
            return Ok(token);
        }

        // On 400/401, parse the error response to determine the specific error
        let body = response.text()?;
        if let Ok(err_resp) = serde_json::from_str::<TokenErrorResponse>(&body) {
            match err_resp.error.as_str() {
                "authorization_pending" => return Err(OidcError::AuthorizationPending),
                "slow_down" => return Err(OidcError::SlowDown),
                "expired_token" => return Err(OidcError::ExpiredToken),
                other => return Err(OidcError::TokenError(other.to_string())),
            }
        }

        Err(OidcError::TokenError(body))
    }

    /// Combined: request device code, display instructions, poll until done.
    ///
    /// `display_fn` is called with `(user_code, verification_uri)` so the
    /// caller (PAM module) can show them to the user.
    pub fn authenticate_device_flow<F>(
        &self,
        scope: &str,
        display_fn: F,
    ) -> Result<TokenResponse, OidcError>
    where
        F: FnOnce(&str, &str),
    {
        let device_auth = self.request_device_code(scope)?;

        display_fn(&device_auth.user_code, &device_auth.verification_uri);

        let interval = std::time::Duration::from_secs(device_auth.interval);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(device_auth.expires_in);

        loop {
            std::thread::sleep(interval);

            if std::time::Instant::now() >= deadline {
                return Err(OidcError::ExpiredToken);
            }

            match self.poll_for_token(&device_auth.device_code) {
                Ok(token) => return Ok(token),
                Err(OidcError::AuthorizationPending) => continue,
                Err(OidcError::SlowDown) => {
                    // Back off by sleeping an extra interval
                    std::thread::sleep(interval);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
