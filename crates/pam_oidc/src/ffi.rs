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

    let username = match unsafe { crate::pam_conv::get_pam_user(pamh) } {
        Ok(u) => u,
        Err(e) => {
            warn!(error = e, "failed to get PAM user");
            return PAM_AUTH_ERR;
        }
    };

    info!(user = %username, "pam_sm_authenticate");

    let client = match crate::state::get_oidc_client() {
        Some(c) => c,
        None => return PAM_AUTHINFO_UNAVAIL,
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
        Ok(token) => {
            let id_token_raw = match token.id_token.as_deref() {
                Some(t) => t,
                None => {
                    warn!(user = %username, "ID token missing — cannot verify subject");
                    return PAM_AUTH_ERR;
                }
            };

            // Validate JWT signature, expiry, issuer, and audience via JWKS.
            let claims = match client.validate_id_token(id_token_raw) {
                Ok(c) => c,
                Err(e) => {
                    warn!(user = %username, error = %e, "ID token validation failed");
                    return PAM_AUTH_ERR;
                }
            };

            let sub = &claims.sub;

            // Verify that the authenticated OIDC subject matches the PAM user.
            // Accept a match if sub == username (simple setups) or if the SCIM
            // user's external id matches the token subject (federated setups
            // where sub is a UUID).
            if sub == &username {
                info!(user = %username, "authentication successful (direct subject match)");
                return PAM_SUCCESS;
            }

            let svc_mutex = match crate::state::get_service() {
                Some(m) => m,
                None => return PAM_AUTH_ERR,
            };
            let svc = svc_mutex.lock().unwrap_or_else(|e| e.into_inner());

            match svc.lookup_user_by_name(&username) {
                Ok(Some(user)) if user.external_id == *sub => {
                    info!(user = %username, sub = %sub, "authentication successful (SCIM id match)");
                    PAM_SUCCESS
                }
                Ok(Some(_)) => {
                    warn!(user = %username, sub = %sub, "token subject does not match user");
                    PAM_AUTH_ERR
                }
                Ok(None) => {
                    warn!(user = %username, "user not found in SCIM during subject verification");
                    PAM_AUTH_ERR
                }
                Err(e) => {
                    warn!(user = %username, error = %e, "SCIM lookup failed during subject verification");
                    PAM_AUTH_ERR
                }
            }
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

    let issuer = match crate::state::get_oidc_client() {
        Some(c) => c.endpoints().issuer.clone(),
        None => return PAM_AUTHTOK_ERR,
    };

    let msg = format!(
        "Password changes are not supported via PAM for OIDC accounts.\n\
         Please change your password at your identity provider:\n  {}",
        issuer
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

    let username = match unsafe { crate::pam_conv::get_pam_user(pamh) } {
        Ok(u) => u,
        Err(e) => {
            warn!(error = e, "failed to get PAM user");
            return PAM_AUTH_ERR;
        }
    };

    info!(user = %username, "pam_sm_acct_mgmt");

    let svc_mutex = match crate::state::get_service() {
        Some(m) => m,
        None => return PAM_AUTHINFO_UNAVAIL,
    };
    let svc = svc_mutex.lock().unwrap_or_else(|e| e.into_inner());

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
