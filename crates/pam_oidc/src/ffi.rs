use libc::c_int;

/// PAM return codes (from <security/pam_modules.h>).
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_IGNORE: c_int = 25;

/// PAM handle (opaque — we never dereference it, only pass it through).
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

/// Authenticate the user via OIDC device code flow.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle provided by the PAM framework.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    // TODO: implement OIDC device code authentication
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

/// Account management — check if user is active/authorized.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    // TODO: check SCIM user `active` flag and group-based access rules
    PAM_SUCCESS
}
