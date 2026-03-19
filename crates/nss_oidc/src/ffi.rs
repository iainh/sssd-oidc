use std::sync::Mutex;

use libc::{c_char, c_int, gid_t, group, passwd, size_t, uid_t};

use crate::group::fill_group;
use crate::passwd::fill_passwd;
use crate::state::get_state;

use tracing::{trace, warn};

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

// --- initgroups_dyn (supplementary group lookup) ---

/// Return supplementary group IDs for a user.
///
/// Called by `initgroups(3)` via glibc's NSS machinery. Writes GIDs into
/// the caller-provided `*groups` array, growing it via `*size` if needed.
///
/// # Safety
///
/// All pointer arguments must be valid. `*groups` must point to a buffer of
/// at least `*size` `gid_t` entries. The caller manages allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_initgroups_dyn(
    user: *const c_char,
    group: gid_t,
    start: *mut libc::c_long,
    size: *mut libc::c_long,
    groupsp: *mut *mut gid_t,
    _limit: libc::c_long,
    errnop: *mut c_int,
) -> NssStatus {
    let user_str = match unsafe { std::ffi::CStr::from_ptr(user) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = 0 };
            return NssStatus::NotFound;
        }
    };
    trace!(user = user_str, "initgroups_dyn");

    let state = match get_state() {
        Some(s) => s,
        None => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };
    let svc = match state.service.lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };

    let gids = match svc.lookup_groups_for_user(user_str) {
        Ok(g) => g,
        Err(e) => {
            warn!(user = user_str, error = %e, "initgroups lookup failed");
            unsafe { *errnop = 0 };
            return NssStatus::Unavail;
        }
    };

    unsafe {
        let groups_buf = *groupsp;
        let cur_start = *start as usize;
        let cur_size = *size as usize;

        for gid in gids {
            // Skip the primary group (already known) and duplicates
            if gid == group {
                continue;
            }
            let mut already_present = false;
            for i in 0..cur_start {
                if *groups_buf.add(i) == gid {
                    already_present = true;
                    break;
                }
            }
            if already_present {
                continue;
            }

            // Check if we have room
            if *start as usize >= cur_size {
                // We can't realloc here — return what we have
                *errnop = libc::ERANGE;
                return NssStatus::TryAgain;
            }

            *groups_buf.add(*start as usize) = gid;
            *start += 1;
        }

        *errnop = 0;
    }

    NssStatus::Success
}

// --- User enumeration (setpwent / getpwent_r / endpwent) ---

/// Begin user enumeration: fetch all users from SCIM.
///
/// # Safety
///
/// Called by glibc's NSS dispatcher. No pointer arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_setpwent() -> NssStatus {
    trace!("setpwent");
    let st = match get_state() {
        Some(s) => s,
        None => return NssStatus::Unavail,
    };

    // Fetch users from SCIM without holding the service mutex
    let scim_users = match st.scim.list_users() {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "setpwent: SCIM list failed");
            return NssStatus::Unavail;
        }
    };

    // Acquire lock only for cache/mapping operations
    let svc = match st.service.lock() {
        Ok(s) => s,
        Err(_) => return NssStatus::Unavail,
    };
    let mut users = Vec::with_capacity(scim_users.len());
    for su in &scim_users {
        match svc.scim_user_to_model(su) {
            Ok(user) => {
                let _ = svc.cache().store_user(&user);
                users.push(user);
            }
            Err(e) => {
                warn!(error = %e, "setpwent: failed to convert SCIM user");
            }
        }
    }
    drop(svc);

    if let Ok(mut enum_state) = USER_ENUM.lock() {
        *enum_state = Some((users, 0));
    }
    NssStatus::Success
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
///
/// # Safety
///
/// Called by glibc's NSS dispatcher. No pointer arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_endpwent() -> NssStatus {
    if let Ok(mut state) = USER_ENUM.lock() {
        *state = None;
    }
    NssStatus::Success
}

// --- Group enumeration (setgrent / getgrent_r / endgrent) ---

/// Begin group enumeration: fetch all groups from SCIM.
///
/// # Safety
///
/// Called by glibc's NSS dispatcher. No pointer arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_setgrent() -> NssStatus {
    trace!("setgrent");
    let st = match get_state() {
        Some(s) => s,
        None => return NssStatus::Unavail,
    };

    // Fetch groups from SCIM without holding the service mutex
    let scim_groups = match st.scim.list_groups() {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "setgrent: SCIM list failed");
            return NssStatus::Unavail;
        }
    };

    // Acquire lock only for cache/mapping operations
    let svc = match st.service.lock() {
        Ok(s) => s,
        Err(_) => return NssStatus::Unavail,
    };
    let mut groups = Vec::with_capacity(scim_groups.len());
    for sg in &scim_groups {
        match svc.scim_group_to_model(sg) {
            Ok(group) => {
                let _ = svc.cache().store_group(&group);
                groups.push(group);
            }
            Err(e) => {
                warn!(error = %e, "setgrent: failed to convert SCIM group");
            }
        }
    }
    drop(svc);

    if let Ok(mut enum_state) = GROUP_ENUM.lock() {
        *enum_state = Some((groups, 0));
    }
    NssStatus::Success
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
///
/// # Safety
///
/// Called by glibc's NSS dispatcher. No pointer arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_oidc_endgrent() -> NssStatus {
    if let Ok(mut state) = GROUP_ENUM.lock() {
        *state = None;
    }
    NssStatus::Success
}
