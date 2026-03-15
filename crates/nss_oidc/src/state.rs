use std::sync::{Mutex, OnceLock};

use sssd_oidc::cache::Cache;
use sssd_oidc::config::Config;
use sssd_oidc::logging;
use sssd_oidc::scim::ScimClient;
use sssd_oidc::service::Service;

use tracing::warn;

static SERVICE: OnceLock<Option<Mutex<Service>>> = OnceLock::new();

/// Get a reference to the shared Service singleton (behind a Mutex because
/// `rusqlite::Connection` is not `Sync`).
/// Initialises config, SCIM client, and cache on first call.
/// Returns `None` if initialisation fails.
pub(crate) fn get_service() -> Option<&'static Mutex<Service>> {
    SERVICE
        .get_or_init(|| {
            logging::init("sssd_oidc", logging::FACILITY_DAEMON);
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
