use libc::c_int;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

/// PAM return codes (from <security/pam_modules.h>).
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTHTOK_ERR: c_int = 20;
pub const PAM_IGNORE: c_int = 25;

/// PAM handle (opaque — we never dereference it, only pass it through).
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

/// Authenticate the user via OIDC device code flow.
///
/// On non-Linux platforms (no libpam), this returns PAM_AUTH_ERR.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle provided by the PAM framework.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    authenticate_impl(pamh)
}

#[cfg(target_os = "linux")]
fn authenticate_impl(pamh: *mut PamHandle) -> c_int {
    sssd_oidc::logging::init("pam_oidc", sssd_oidc::logging::FACILITY_AUTHPRIV);

    use sssd_oidc::config::Config;
    use sssd_oidc::oidc::OidcClient;

    let username = match unsafe { crate::pam_conv::get_pam_user(pamh) } {
        Ok(u) => u,
        Err(e) => {
            warn!(error = e, "failed to get PAM user");
            return PAM_AUTH_ERR;
        }
    };

    info!(user = %username, "pam_sm_authenticate");

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to load config");
            return PAM_AUTHINFO_UNAVAIL;
        }
    };

    let client = match OidcClient::discover(
        &config.oidc.issuer_url,
        &config.oidc.client_id,
        config.oidc.client_secret.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "OIDC discovery failed");
            return PAM_AUTHINFO_UNAVAIL;
        }
    };

    let result = client.authenticate_device_flow("openid", |user_code, verification_uri| {
        let msg = format!(
            "To sign in, visit: {verification_uri}\nEnter code: {user_code}\nWaiting for authentication..."
        );
        unsafe {
            crate::pam_conv::pam_info(pamh, &msg);
        }
    });

    match result {
        Ok(_token) => {
            // TODO: optionally verify token subject matches username
            info!(user = %username, "authentication successful");
            PAM_SUCCESS
        }
        Err(e) => {
            warn!(user = %username, error = %e, "authentication failed");
            PAM_AUTH_ERR
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn authenticate_impl(_pamh: *mut PamHandle) -> c_int {
    // PAM functions (pam_get_user, pam_get_item) are only available on Linux
    PAM_AUTH_ERR
}

/// Set credentials (no-op for OIDC).
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Password change — not supported for OIDC.
///
/// Returns PAM_AUTHTOK_ERR to indicate the user should change their password
/// via the IdP's web portal instead.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    chauthtok_impl(pamh)
}

#[cfg(target_os = "linux")]
fn chauthtok_impl(pamh: *mut PamHandle) -> c_int {
    sssd_oidc::logging::init("pam_oidc", sssd_oidc::logging::FACILITY_AUTHPRIV);
    info!("pam_sm_chauthtok: redirecting to IdP");

    use sssd_oidc::config::Config;

    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => return PAM_AUTHTOK_ERR,
    };

    let msg = format!(
        "Password changes are not supported via PAM for OIDC accounts.\n\
         Please change your password at your identity provider:\n  {}",
        config.oidc.issuer_url
    );
    unsafe {
        crate::pam_conv::pam_info(pamh, &msg);
    }
    PAM_AUTHTOK_ERR
}

#[cfg(not(target_os = "linux"))]
fn chauthtok_impl(_pamh: *mut PamHandle) -> c_int {
    PAM_AUTHTOK_ERR
}

/// Account management — check if user is active/authorized.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    acct_mgmt_impl(pamh)
}

#[cfg(target_os = "linux")]
fn acct_mgmt_impl(pamh: *mut PamHandle) -> c_int {
    sssd_oidc::logging::init("pam_oidc", sssd_oidc::logging::FACILITY_AUTHPRIV);

    use sssd_oidc::cache::Cache;
    use sssd_oidc::config::Config;
    use sssd_oidc::scim::ScimClient;
    use sssd_oidc::service::Service;

    let username = match unsafe { crate::pam_conv::get_pam_user(pamh) } {
        Ok(u) => u,
        Err(e) => {
            warn!(error = e, "failed to get PAM user");
            return PAM_AUTH_ERR;
        }
    };

    info!(user = %username, "pam_sm_acct_mgmt");

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to load config");
            return PAM_AUTHINFO_UNAVAIL;
        }
    };

    let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
    let cache = match Cache::open(&config.cache.db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to open cache");
            return PAM_AUTHINFO_UNAVAIL;
        }
    };
    let svc = Service::new(config, scim, cache);

    match svc.check_user_active(&username) {
        Ok(true) => {
            info!(user = %username, "account permitted");
            PAM_SUCCESS
        }
        Ok(false) => {
            warn!(user = %username, "account denied (inactive)");
            PAM_PERM_DENIED
        }
        Err(e) => {
            warn!(user = %username, error = %e, "account check failed");
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn acct_mgmt_impl(_pamh: *mut PamHandle) -> c_int {
    PAM_SUCCESS
}
