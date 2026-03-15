use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::info;

/// Default config file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/sssd-oidc/config.toml";

/// Default bearer token file path.
const DEFAULT_BEARER_TOKEN_PATH: &str = "/etc/sssd-oidc/scim-token";

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
    #[error("insecure permissions on {path}: {detail}")]
    InsecurePermissions { path: PathBuf, detail: String },
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
    /// Path to file containing the SCIM bearer token (default: `/etc/sssd-oidc/scim-token`).
    /// The file must be owned by root and have mode 0600 or 0400.
    #[serde(default = "default_bearer_token_file")]
    pub bearer_token_file: PathBuf,
    /// Populated at load time from `bearer_token_file`; not deserialized from TOML.
    #[serde(skip)]
    pub bearer_token: String,
}

fn default_bearer_token_file() -> PathBuf {
    PathBuf::from(DEFAULT_BEARER_TOKEN_PATH)
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
        info!(path = %path.display(), "loading configuration");
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut config: Config = toml::from_str(&contents)?;

        let token_path = &config.scim.bearer_token_file;
        check_secret_file_permissions(token_path)?;

        let token = std::fs::read_to_string(token_path).map_err(|source| ConfigError::Read {
            path: token_path.to_owned(),
            source,
        })?;
        config.scim.bearer_token = token.trim().to_string();

        info!(path = %path.display(), "configuration loaded");
        Ok(config)
    }
}

/// Verify that a secrets file has restrictive permissions.
///
/// Refuses to proceed if the file is not a regular file, or if group/other
/// bits are set (i.e. anything more permissive than `0600`). On Linux,
/// also requires root ownership.
///
/// Follows the same pattern as OpenSSH's private-key check and SSSD's
/// config-file check — hard fail, actionable error message.
#[cfg(unix)]
fn check_secret_file_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;

    if !meta.is_file() {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: "not a regular file".into(),
        });
    }

    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: format!(
                "permissions {:04o} are too open; must not be accessible by group or others. \
                 Run: chmod 600 {}",
                mode & 0o777,
                path.display()
            ),
        });
    }

    #[cfg(target_os = "linux")]
    if meta.uid() != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: format!(
                "owned by uid {} but must be owned by root (uid 0)",
                meta.uid()
            ),
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_secret_file_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: create a temp token file with mode 0600 and return it + its path string.
    fn make_token_file(token: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create temp token file");
        f.write_all(token.as_bytes()).unwrap();
        f.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        f
    }

    /// Helper: write a config toml pointing at the given token file, load it.
    fn load_test_config(token_path: &Path) -> Config {
        let toml_content = format!(
            r#"
[scim]
base_url = "https://example.okta.com/scim/v2"
bearer_token_file = "{}"

[oidc]
issuer_url = "https://example.okta.com"
client_id = "my-client"
"#,
            token_path.display()
        );
        let mut cfg_file = NamedTempFile::new().expect("create temp config");
        cfg_file.write_all(toml_content.as_bytes()).unwrap();
        cfg_file.flush().unwrap();
        Config::load_from(cfg_file.path()).expect("load config")
    }

    #[test]
    fn parse_minimal_config() {
        let token_file = make_token_file("test-token");
        let config = load_test_config(token_file.path());
        assert_eq!(config.scim.base_url, "https://example.okta.com/scim/v2");
        assert_eq!(config.scim.bearer_token, "test-token");
        assert_eq!(config.mapping.uid_range_min, 200_000);
        assert_eq!(config.user_defaults.shell, "/bin/bash");
    }

    #[test]
    fn token_file_whitespace_trimmed() {
        let token_file = make_token_file("  my-token\n");
        let config = load_test_config(token_file.path());
        assert_eq!(config.scim.bearer_token, "my-token");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_token_file() {
        use std::os::unix::fs::PermissionsExt;
        let token_file = make_token_file("secret");
        std::fs::set_permissions(token_file.path(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let toml_content = format!(
            r#"
[scim]
base_url = "https://example.com/scim/v2"
bearer_token_file = "{}"

[oidc]
issuer_url = "https://example.com"
client_id = "test"
"#,
            token_file.path().display()
        );
        let mut cfg_file = NamedTempFile::new().unwrap();
        cfg_file.write_all(toml_content.as_bytes()).unwrap();
        cfg_file.flush().unwrap();
        let err = Config::load_from(cfg_file.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too open"), "expected 'too open' in: {msg}");
        assert!(msg.contains("0644"), "expected '0644' in: {msg}");
    }
}
