use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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
    #[error("ID token missing from response")]
    MissingIdToken,
    #[error("ID token subject \"{token_sub}\" does not match user \"{expected}\"")]
    SubjectMismatch { token_sub: String, expected: String },
    #[error("failed to decode ID token: {0}")]
    IdTokenDecode(String),
    #[error("JWT validation failed: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),
}

/// Endpoints parsed from the OIDC discovery document.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub issuer: String,
    pub jwks_uri: String,
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
    http: ureq::Agent,
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
    jwks_uri: Option<String>,
}

impl OidcClient {
    /// Discover endpoints from `{issuer_url}/.well-known/openid-configuration`
    /// and create an OIDC client.
    pub fn discover(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, OidcError> {
        info!(issuer_url, "discovering OIDC endpoints");
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build();
        let http: ureq::Agent = config.into();
        let doc: DiscoveryDocument = http.get(&url).call()?.body_mut().read_json()?;

        let issuer = doc
            .issuer
            .ok_or_else(|| OidcError::MissingField("issuer".into()))?;
        let token_endpoint = doc
            .token_endpoint
            .ok_or_else(|| OidcError::MissingField("token_endpoint".into()))?;
        let device_authorization_endpoint = doc
            .device_authorization_endpoint
            .ok_or_else(|| OidcError::MissingField("device_authorization_endpoint".into()))?;
        let jwks_uri = doc
            .jwks_uri
            .ok_or_else(|| OidcError::MissingField("jwks_uri".into()))?;

        info!(issuer = issuer, "OIDC discovery complete");
        Ok(Self {
            http,
            endpoints: OidcEndpoints {
                device_authorization_endpoint,
                token_endpoint,
                issuer,
                jwks_uri,
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
        info!(scope, "requesting device code");
        let mut form: Vec<(&str, &str)> =
            vec![("client_id", self.client_id.as_str()), ("scope", scope)];
        if let Some(ref secret) = self.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let resp: DeviceAuthResponse = self
            .http
            .post(&self.endpoints.device_authorization_endpoint)
            .send_form(form)?
            .body_mut()
            .read_json()?;
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
        debug!("polling for token");
        let mut form: Vec<(&str, &str)> = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ];
        if let Some(ref secret) = self.client_secret {
            form.push(("client_secret", secret.as_str()));
        }

        // Disable http_status_as_error so we can inspect 4xx response bodies
        let result = self
            .http
            .post(&self.endpoints.token_endpoint)
            .config()
            .http_status_as_error(false)
            .build()
            .send_form(form);

        let mut response = result?;
        let status = response.status().as_u16();

        if (200..300).contains(&status) {
            let token: TokenResponse = response.body_mut().read_json()?;
            return Ok(token);
        }

        // On 4xx/5xx, parse the error response to determine the specific error
        let body = response.body_mut().read_to_string()?;
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
        info!("starting device code authentication flow");
        let device_auth = self.request_device_code(scope)?;

        display_fn(&device_auth.user_code, &device_auth.verification_uri);

        let interval = std::time::Duration::from_secs(device_auth.interval);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(device_auth.expires_in);

        loop {
            std::thread::sleep(interval);

            if std::time::Instant::now() >= deadline {
                warn!("device code expired");
                return Err(OidcError::ExpiredToken);
            }

            match self.poll_for_token(&device_auth.device_code) {
                Ok(token) => {
                    info!("device code authentication successful");
                    return Ok(token);
                }
                Err(OidcError::AuthorizationPending) => {
                    debug!("authorization pending, waiting");
                    continue;
                }
                Err(OidcError::SlowDown) => {
                    debug!("slowing down polling interval");
                    std::thread::sleep(interval);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Validate an ID token's signature, expiry, issuer, and audience using
    /// the IdP's JWKS, then return the validated claims.
    ///
    /// Fetches the JWKS from the discovered `jwks_uri`, selects the key
    /// matching the token's `kid` header, and validates per OIDC Core §3.1.3.7.
    pub fn validate_id_token(&self, id_token: &str) -> Result<IdTokenClaims, OidcError> {
        use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

        let header = decode_header(id_token)?;

        // Fetch the JWKS from the IdP
        let jwks: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(&self.endpoints.jwks_uri)
            .call()?
            .body_mut()
            .read_json()?;

        // Find the key matching the token's kid
        let jwk = match &header.kid {
            Some(kid) => jwks
                .find(kid)
                .ok_or_else(|| OidcError::IdTokenDecode(format!("no JWK with kid \"{kid}\"")))?,
            None => jwks
                .keys
                .first()
                .ok_or_else(|| OidcError::IdTokenDecode("JWKS is empty".into()))?,
        };

        let decoding_key = DecodingKey::from_jwk(jwk)?;

        let alg = header.alg;
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.endpoints.issuer]);
        validation.set_audience(&[&self.client_id]);
        // Require sub, exp, iss, aud
        validation.set_required_spec_claims(&["sub", "exp", "iss"]);
        // aud validation is handled by validate_aud + set_audience above
        validation.validate_exp = true;

        let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)?;

        info!(sub = %token_data.claims.sub, "ID token validated successfully");
        Ok(token_data.claims)
    }
}

/// Validated ID token claims (OIDC Core §2).
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    /// Subject identifier — unique ID for the authenticated user.
    pub sub: String,
    /// Issuer URL.
    pub iss: String,
    /// Audience (client_id).
    pub aud: serde_json::Value,
    /// Expiration time (UTC timestamp).
    pub exp: u64,
    /// Issued-at time (UTC timestamp).
    #[serde(default)]
    pub iat: Option<u64>,
}

/// Decode the payload of a JWT ID token (without cryptographic verification)
/// and extract the `sub` claim.
///
/// We skip signature verification because the token was received over TLS
/// directly from the IdP's token endpoint.
pub fn extract_id_token_subject(id_token: &str) -> Result<String, OidcError> {
    use base64::prelude::*;

    let parts: Vec<&str> = id_token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(OidcError::IdTokenDecode("not a valid JWT".into()));
    }

    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OidcError::IdTokenDecode(format!("base64: {e}")))?;

    #[derive(Deserialize)]
    struct Claims {
        sub: Option<String>,
    }

    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| OidcError::IdTokenDecode(format!("json: {e}")))?;

    claims
        .sub
        .ok_or_else(|| OidcError::IdTokenDecode("missing sub claim".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    fn make_jwt(claims_json: &str) -> String {
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(claims_json);
        format!("{header}.{payload}.fake-signature")
    }

    #[test]
    fn extract_subject_from_valid_jwt() {
        let jwt = make_jwt(r#"{"sub":"user-uuid-alice-001","iss":"https://idp.example.com"}"#);
        let sub = extract_id_token_subject(&jwt).unwrap();
        assert_eq!(sub, "user-uuid-alice-001");
    }

    #[test]
    fn extract_subject_missing_sub_claim() {
        let jwt = make_jwt(r#"{"iss":"https://idp.example.com"}"#);
        let err = extract_id_token_subject(&jwt).unwrap_err();
        assert!(err.to_string().contains("missing sub claim"));
    }

    #[test]
    fn extract_subject_invalid_jwt_format() {
        let err = extract_id_token_subject("not-a-jwt").unwrap_err();
        assert!(err.to_string().contains("not a valid JWT"));
    }
}
