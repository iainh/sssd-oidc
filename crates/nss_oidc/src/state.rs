use std::sync::{Mutex, OnceLock};

use sssd_oidc::cache::Cache;
use sssd_oidc::config::Config;
use sssd_oidc::logging;
use sssd_oidc::scim::ScimClient;
use sssd_oidc::service::Service;

use tracing::warn;

/// NSS shared state.
///
/// `ScimClient` is `Send + Sync` and does not need a mutex — it only
/// performs stateless HTTP requests. Holding the `Service` mutex across
/// blocking SCIM calls would serialise all NSS lookups behind a single
/// lock, so we keep the SCIM client outside the lock and only acquire
/// the `Mutex<Service>` for cache/mapping operations.
pub(crate) struct NssState {
    pub scim: ScimClient,
    pub service: Mutex<Service>,
}

static STATE: OnceLock<Option<NssState>> = OnceLock::new();

/// Get a reference to the shared NSS state singleton.
/// Initialises config, SCIM client, and cache on first call.
/// Returns `None` if initialisation fails.
pub(crate) fn get_state() -> Option<&'static NssState> {
    STATE
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
            // Create a second ScimClient for the Service (ScimClient is cheap to clone-like construct)
            let svc_scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
            Some(NssState {
                scim,
                service: Mutex::new(Service::new(config, svc_scim, cache)),
            })
        })
        .as_ref()
}
