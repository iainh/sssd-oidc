pub(crate) mod fill_passwd {
    use libc::{ERANGE, c_char, c_int, passwd, size_t, uid_t};

    use crate::ffi::NssStatus;

    /// Look up a user by name and fill the passwd struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_name(
        _name: *const c_char,
        _result: *mut passwd,
        _buf: *mut c_char,
        _buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        // TODO: call sssd_oidc::service to resolve user
        unsafe {
            *errnop = 0;
        }
        NssStatus::NotFound
    }

    /// Look up a user by UID and fill the passwd struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_uid(
        _uid: uid_t,
        _result: *mut passwd,
        _buf: *mut c_char,
        _buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        // TODO: call sssd_oidc::service to resolve user by UID
        unsafe {
            *errnop = 0;
        }
        NssStatus::NotFound
    }

    /// Write a C string into the buffer, advancing the offset.
    /// Returns `None` if the buffer is too small.
    #[allow(dead_code)]
    pub(crate) unsafe fn write_str(
        buf: *mut c_char,
        buflen: size_t,
        offset: &mut usize,
        s: &str,
    ) -> Option<*mut c_char> {
        let needed = s.len() + 1; // +1 for NUL
        if *offset + needed > buflen {
            return None;
        }
        let ptr = unsafe { buf.add(*offset) };
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, ptr, s.len());
            *ptr.add(s.len()) = 0; // NUL terminator
        }
        *offset += needed;
        Some(ptr)
    }

    /// Set `*errnop = ERANGE` and return `TryAgain`.
    #[allow(dead_code)]
    pub(crate) unsafe fn buffer_too_small(errnop: *mut c_int) -> NssStatus {
        unsafe {
            *errnop = ERANGE;
        }
        NssStatus::TryAgain
    }
}
