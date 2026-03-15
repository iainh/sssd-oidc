use std::sync::{Mutex, OnceLock};

use sssd_oidc::cache::Cache;
use sssd_oidc::config::Config;
use sssd_oidc::logging;
use sssd_oidc::oidc::OidcClient;
use sssd_oidc::scim::ScimClient;
use sssd_oidc::service::Service;

use tracing::warn;

static SERVICE: OnceLock<Option<Mutex<Service>>> = OnceLock::new();
static OIDC_CLIENT: OnceLock<Option<OidcClient>> = OnceLock::new();

/// Get a reference to the shared Service singleton (behind a Mutex because
/// `rusqlite::Connection` is not `Sync`).
/// Initialises config, SCIM client, and cache on first call.
/// Returns `None` if initialisation fails.
pub(crate) fn get_service() -> Option<&'static Mutex<Service>> {
    SERVICE
        .get_or_init(|| {
            logging::init("pam_oidc", logging::FACILITY_AUTHPRIV);
            let config = match Config::load() {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to load config");
                    return None;
                }
            };
            let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
            let cache = match Cache::open(&config.cache.db_path, config.cache.ttl_seconds) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to open cache");
                    return None;
                }
            };
            Some(Mutex::new(Service::new(config, scim, cache)))
        })
        .as_ref()
}

/// Get a reference to the shared OidcClient singleton.
/// Performs OIDC discovery on first call; subsequent calls reuse the result.
/// Returns `None` if discovery or config loading fails.
pub(crate) fn get_oidc_client() -> Option<&'static OidcClient> {
    OIDC_CLIENT
        .get_or_init(|| {
            logging::init("pam_oidc", logging::FACILITY_AUTHPRIV);
            let config = match Config::load() {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to load config for OIDC discovery");
                    return None;
                }
            };
            match OidcClient::discover(
                &config.oidc.issuer_url,
                &config.oidc.client_id,
                config.oidc.client_secret.as_deref(),
            ) {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(error = %e, "OIDC discovery failed");
                    None
                }
            }
        })
        .as_ref()
}
