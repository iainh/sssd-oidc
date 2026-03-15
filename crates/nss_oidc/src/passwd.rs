pub(crate) mod fill_passwd {
    use libc::{ERANGE, c_char, c_int, passwd, size_t, uid_t};
    use std::ffi::CStr;

    use crate::ffi::NssStatus;
    use crate::state::get_service;

    use tracing::{trace, warn};

    /// Look up a user by name and fill the passwd struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_name(
        name: *const c_char,
        result: *mut passwd,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                unsafe { *errnop = 0 };
                return NssStatus::NotFound;
            }
        };
        trace!(name = name_str, "getpwnam_r");

        let svc = match get_service() {
            Some(s) => s,
            None => {
                unsafe { *errnop = 0 };
                return NssStatus::Unavail;
            }
        };
        let svc = match svc.lock() {
            Ok(s) => s,
            Err(_) => {
                unsafe { *errnop = 0 };
                return NssStatus::Unavail;
            }
        };

        match svc.lookup_user_by_name(name_str) {
            Ok(Some(user)) => unsafe { fill_passwd_buf(&user, result, buf, buflen, errnop) },
            Ok(None) => {
                unsafe { *errnop = 0 };
                NssStatus::NotFound
            }
            Err(e) => {
                warn!(name = name_str, error = %e, "user lookup failed");
                unsafe { *errnop = 0 };
                NssStatus::Unavail
            }
        }
    }

    /// Look up a user by UID and fill the passwd struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_uid(
        uid: uid_t,
        result: *mut passwd,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        let svc = match get_service() {
            Some(s) => s,
            None => {
                unsafe { *errnop = 0 };
                return NssStatus::Unavail;
            }
        };
        let svc = match svc.lock() {
            Ok(s) => s,
            Err(_) => {
                unsafe { *errnop = 0 };
                return NssStatus::Unavail;
            }
        };
        trace!(uid, "getpwuid_r");

        match svc.lookup_user_by_uid(uid) {
            Ok(Some(user)) => unsafe { fill_passwd_buf(&user, result, buf, buflen, errnop) },
            Ok(None) => {
                unsafe { *errnop = 0 };
                NssStatus::NotFound
            }
            Err(e) => {
                warn!(uid, error = %e, "user lookup by uid failed");
                unsafe { *errnop = 0 };
                NssStatus::Unavail
            }
        }
    }

    /// Fill the `passwd` struct from a `User` model, writing strings into `buf`.
    ///
    /// # Safety
    ///
    /// `result`, `buf`, and `errnop` must be valid pointers. `buf` must be at
    /// least `buflen` bytes.
    pub(crate) unsafe fn fill_passwd_buf(
        user: &sssd_oidc::model::User,
        result: *mut passwd,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        let mut offset: usize = 0;

        let pw_name = match unsafe { write_str(buf, buflen, &mut offset, &user.name) } {
            Some(p) => p,
            None => return unsafe { buffer_too_small(errnop) },
        };
        let pw_passwd = match unsafe { write_str(buf, buflen, &mut offset, "x") } {
            Some(p) => p,
            None => return unsafe { buffer_too_small(errnop) },
        };
        let pw_gecos = match unsafe { write_str(buf, buflen, &mut offset, &user.gecos) } {
            Some(p) => p,
            None => return unsafe { buffer_too_small(errnop) },
        };
        let pw_dir = match unsafe { write_str(buf, buflen, &mut offset, &user.home) } {
            Some(p) => p,
            None => return unsafe { buffer_too_small(errnop) },
        };
        let pw_shell = match unsafe { write_str(buf, buflen, &mut offset, &user.shell) } {
            Some(p) => p,
            None => return unsafe { buffer_too_small(errnop) },
        };

        unsafe {
            (*result).pw_name = pw_name;
            (*result).pw_passwd = pw_passwd;
            (*result).pw_uid = user.uid;
            (*result).pw_gid = user.gid;
            (*result).pw_gecos = pw_gecos;
            (*result).pw_dir = pw_dir;
            (*result).pw_shell = pw_shell;
            *errnop = 0;
        }

        NssStatus::Success
    }

    /// Write a C string into the buffer, advancing the offset.
    /// Returns `None` if the buffer is too small.
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
    unsafe fn buffer_too_small(errnop: *mut c_int) -> NssStatus {
        unsafe {
            *errnop = ERANGE;
        }
        NssStatus::TryAgain
    }
}

#[cfg(test)]
mod tests {
    use super::fill_passwd::write_str;
    use libc::c_char;
    use std::ffi::CStr;

    #[test]
    fn write_str_writes_nul_terminated_string_and_advances_offset() {
        let mut buf = [0i8; 64];
        let mut offset: usize = 0;

        let ptr = unsafe { write_str(buf.as_mut_ptr(), buf.len(), &mut offset, "hello") };
        assert!(ptr.is_some());
        let ptr = ptr.unwrap();

        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(result, "hello");
        assert_eq!(offset, 6); // "hello" + NUL
    }

    #[test]
    fn write_str_returns_none_when_buffer_too_small() {
        let mut buf = [0i8; 3];
        let mut offset: usize = 0;

        // "hello" needs 6 bytes, buffer is only 3
        let ptr = unsafe { write_str(buf.as_mut_ptr(), buf.len(), &mut offset, "hello") };
        assert!(ptr.is_none());
        assert_eq!(offset, 0); // offset unchanged
    }

    #[test]
    fn write_str_consecutive_writes_pack_correctly() {
        let mut buf = [0i8; 64];
        let mut offset: usize = 0;

        let p1 = unsafe { write_str(buf.as_mut_ptr(), buf.len(), &mut offset, "alice") };
        assert!(p1.is_some());
        assert_eq!(offset, 6);

        let p2 = unsafe { write_str(buf.as_mut_ptr(), buf.len(), &mut offset, "x") };
        assert!(p2.is_some());
        assert_eq!(offset, 8); // 6 + "x\0"

        let s1 = unsafe { CStr::from_ptr(p1.unwrap()) }.to_str().unwrap();
        let s2 = unsafe { CStr::from_ptr(p2.unwrap()) }.to_str().unwrap();
        assert_eq!(s1, "alice");
        assert_eq!(s2, "x");
    }

    #[test]
    fn write_str_exact_fit() {
        // "ab" needs 3 bytes (2 chars + NUL), buffer is exactly 3
        let mut buf = [0i8; 3];
        let mut offset: usize = 0;

        let ptr = unsafe { write_str(buf.as_mut_ptr(), buf.len(), &mut offset, "ab") };
        assert!(ptr.is_some());
        assert_eq!(offset, 3);

        // Now buffer is full — next write should fail
        let ptr2 =
            unsafe { write_str(buf.as_mut_ptr() as *mut c_char, buf.len(), &mut offset, "c") };
        assert!(ptr2.is_none());
    }
}
