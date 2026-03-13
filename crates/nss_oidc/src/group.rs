pub(crate) mod fill_group {
    use libc::{c_char, c_int, gid_t, group, size_t};

    use crate::ffi::NssStatus;

    /// Look up a group by name and fill the group struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_name(
        _name: *const c_char,
        _result: *mut group,
        _buf: *mut c_char,
        _buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        // TODO: call sssd_oidc::service to resolve group
        unsafe {
            *errnop = 0;
        }
        NssStatus::NotFound
    }

    /// Look up a group by GID and fill the group struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_gid(
        _gid: gid_t,
        _result: *mut group,
        _buf: *mut c_char,
        _buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        // TODO: call sssd_oidc::service to resolve group by GID
        unsafe {
            *errnop = 0;
        }
        NssStatus::NotFound
    }
}
