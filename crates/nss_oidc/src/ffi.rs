use std::sync::Mutex;

use libc::{c_char, c_int, gid_t, group, passwd, size_t, uid_t};

use crate::group::fill_group;
use crate::passwd::fill_passwd;
use crate::state::get_service;

/// Enumeration state for setpwent/getpwent_r/endpwent cycle.
static USER_ENUM: Mutex<Option<(Vec<sssd_oidc::model::User>, usize)>> = Mutex::new(None);
/// Enumeration state for setgrent/getgrent_r/endgrent cycle.
static GROUP_ENUM: Mutex<Option<(Vec<sssd_oidc::model::Group>, usize)>> = Mutex::new(None);

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

// --- User enumeration (setpwent / getpwent_r / endpwent) ---

/// Begin user enumeration: fetch all users from SCIM.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_setpwent() -> NssStatus {
    let svc = match get_service() {
        Some(s) => s,
        None => return NssStatus::Unavail,
    };
    let svc = match svc.lock() {
        Ok(s) => s,
        Err(_) => return NssStatus::Unavail,
    };
    match svc.list_all_users() {
        Ok(users) => {
            if let Ok(mut state) = USER_ENUM.lock() {
                *state = Some((users, 0));
            }
            NssStatus::Success
        }
        Err(_) => NssStatus::Unavail,
    }
}

/// Return the next user in the enumeration.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getpwent_r(
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let mut state = match USER_ENUM.lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };
    let (users, idx) = match state.as_mut() {
        Some(s) => s,
        None => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };
    if *idx >= users.len() {
        unsafe { *errnop = 0 };
        return NssStatus::NotFound;
    }
    let user = &users[*idx];
    let status = unsafe { fill_passwd::fill_passwd_buf(user, result, buf, buflen, errnop) };
    if status == NssStatus::Success {
        *idx += 1;
    }
    status
}

/// End user enumeration: free the state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_endpwent() -> NssStatus {
    if let Ok(mut state) = USER_ENUM.lock() {
        *state = None;
    }
    NssStatus::Success
}

// --- Group enumeration (setgrent / getgrent_r / endgrent) ---

/// Begin group enumeration: fetch all groups from SCIM.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_setgrent() -> NssStatus {
    let svc = match get_service() {
        Some(s) => s,
        None => return NssStatus::Unavail,
    };
    let svc = match svc.lock() {
        Ok(s) => s,
        Err(_) => return NssStatus::Unavail,
    };
    match svc.list_all_groups() {
        Ok(groups) => {
            if let Ok(mut state) = GROUP_ENUM.lock() {
                *state = Some((groups, 0));
            }
            NssStatus::Success
        }
        Err(_) => NssStatus::Unavail,
    }
}

/// Return the next group in the enumeration.
///
/// # Safety
///
/// Caller must provide valid pointers and buffer of at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_getgrent_r(
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let mut state = match GROUP_ENUM.lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };
    let (groups, idx) = match state.as_mut() {
        Some(s) => s,
        None => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };
    if *idx >= groups.len() {
        unsafe { *errnop = 0 };
        return NssStatus::NotFound;
    }
    let grp = &groups[*idx];
    let status = unsafe { fill_group::fill_group_buf(grp, result, buf, buflen, errnop) };
    if status == NssStatus::Success {
        *idx += 1;
    }
    status
}

/// End group enumeration: free the state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_endgrent() -> NssStatus {
    if let Ok(mut state) = GROUP_ENUM.lock() {
        *state = None;
    }
    NssStatus::Success
}
