use libc::{c_char, c_int, gid_t, group, passwd, size_t, uid_t};

use crate::group::fill_group;
use crate::passwd::fill_passwd;

/// NSS status codes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
}

/// Look up a user by name.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getpwnam_r(
    name: *const c_char,
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { fill_passwd::by_name(name, result, buf, buflen, errnop) }
}

/// Look up a user by UID.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getpwuid_r(
    uid: uid_t,
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { fill_passwd::by_uid(uid, result, buf, buflen, errnop) }
}

/// Look up a group by name.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getgrnam_r(
    name: *const c_char,
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { fill_group::by_name(name, result, buf, buflen, errnop) }
}

/// Look up a group by GID.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getgrgid_r(
    gid: gid_t,
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { fill_group::by_gid(gid, result, buf, buflen, errnop) }
}
