use std::sync::{Mutex, OnceLock};

use sssd_oidc::cache::Cache;
use sssd_oidc::config::Config;
use sssd_oidc::scim::ScimClient;
use sssd_oidc::service::Service;

static SERVICE: OnceLock<Option<Mutex<Service>>> = OnceLock::new();

/// Get a reference to the shared Service singleton (behind a Mutex because
/// `rusqlite::Connection` is not `Sync`).
/// Initialises config, SCIM client, and cache on first call.
/// Returns `None` if initialisation fails.
pub(crate) fn get_service() -> Option<&'static Mutex<Service>> {
    SERVICE
        .get_or_init(|| {
            let config = Config::load().ok()?;
            let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
            let cache = Cache::open(&config.cache.db_path).ok()?;
            Some(Mutex::new(Service::new(config, scim, cache)))
        })
        .as_ref()
}
