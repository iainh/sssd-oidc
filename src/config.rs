use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Default config file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/sssd-oidc/config.toml";

/// Environment variable to override the config file path.
const CONFIG_ENV_VAR: &str = "SSSD_OIDC_CONFIG";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub scim: ScimConfig,
    pub oidc: OidcConfig,
    #[serde(default)]
    pub mapping: MappingConfig,
    #[serde(default)]
    pub user_defaults: UserDefaultsConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScimConfig {
    /// Base URL for the SCIM 2.0 endpoint (e.g. `https://example.okta.com/scim/v2`).
    pub base_url: String,
    /// Bearer token for SCIM API authentication.
    pub bearer_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (used for discovery via `.well-known/openid-configuration`).
    pub issuer_url: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret (optional, depends on IdP config).
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MappingConfig {
    #[serde(default = "default_range_min")]
    pub uid_range_min: u32,
    #[serde(default = "default_range_size")]
    pub uid_range_size: u32,
    #[serde(default = "default_range_min")]
    pub gid_range_min: u32,
    #[serde(default = "default_range_size")]
    pub gid_range_size: u32,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            uid_range_min: default_range_min(),
            uid_range_size: default_range_size(),
            gid_range_min: default_range_min(),
            gid_range_size: default_range_size(),
        }
    }
}

fn default_range_min() -> u32 {
    200_000
}

fn default_range_size() -> u32 {
    200_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserDefaultsConfig {
    #[serde(default = "default_shell")]
    pub shell: String,
    #[serde(default = "default_home_template")]
    pub home_template: String,
}

impl Default for UserDefaultsConfig {
    fn default() -> Self {
        Self {
            shell: default_shell(),
            home_template: default_home_template(),
        }
    }
}

fn default_shell() -> String {
    "/bin/bash".to_string()
}

fn default_home_template() -> String {
    "/home/{user}".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Path to the SQLite cache database.
    #[serde(default = "default_cache_path")]
    pub db_path: String,
    /// Cache entry TTL in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            db_path: default_cache_path(),
            ttl_seconds: default_cache_ttl(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_cache_path() -> String {
    "/var/lib/sssd-oidc/cache.db".to_string()
}

impl Config {
    /// Load configuration from the default path or `SSSD_OIDC_CONFIG` env var.
    pub fn load() -> Result<Self, ConfigError> {
        let path = std::env::var(CONFIG_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH));
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[scim]
base_url = "https://example.okta.com/scim/v2"
bearer_token = "test-token"

[oidc]
issuer_url = "https://example.okta.com"
client_id = "my-client"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.scim.base_url, "https://example.okta.com/scim/v2");
        assert_eq!(config.mapping.uid_range_min, 200_000);
        assert_eq!(config.user_defaults.shell, "/bin/bash");
    }
}
