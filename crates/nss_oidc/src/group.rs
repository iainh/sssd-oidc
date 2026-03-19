pub(crate) mod fill_group {
    use libc::{ERANGE, c_char, c_int, gid_t, group, size_t};
    use std::ffi::CStr;

    use crate::ffi::NssStatus;
    use crate::passwd::fill_passwd::write_str;
    use crate::state::get_state;

    use tracing::{trace, warn};

    /// Look up a group by name and fill the group struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_name(
        name: *const c_char,
        result: *mut group,
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
        trace!(name = name_str, "getgrnam_r");

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

        match svc.lookup_group_by_name(name_str) {
            Ok(Some(grp)) => unsafe { fill_group_buf(&grp, result, buf, buflen, errnop) },
            Ok(None) => {
                unsafe { *errnop = 0 };
                NssStatus::NotFound
            }
            Err(e) => {
                warn!(name = name_str, error = %e, "group lookup failed");
                unsafe { *errnop = 0 };
                NssStatus::Unavail
            }
        }
    }

    /// Look up a group by GID and fill the group struct.
    ///
    /// # Safety
    ///
    /// All pointer arguments must be valid.
    pub(crate) unsafe fn by_gid(
        gid: gid_t,
        result: *mut group,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
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
        trace!(gid, "getgrgid_r");

        match svc.lookup_group_by_gid(gid) {
            Ok(Some(grp)) => unsafe { fill_group_buf(&grp, result, buf, buflen, errnop) },
            Ok(None) => {
                unsafe { *errnop = 0 };
                NssStatus::NotFound
            }
            Err(e) => {
                warn!(gid, error = %e, "group lookup by gid failed");
                unsafe { *errnop = 0 };
                NssStatus::Unavail
            }
        }
    }

    /// Fill the `group` struct from a `Group` model, writing strings and the
    /// `gr_mem` pointer array into `buf`.
    ///
    /// Buffer layout:
    /// ```text
    /// [ "gr_name\0" | "x\0" | "member1\0" | "member2\0" | <align> | ptr1 | ptr2 | NULL ]
    /// ```
    ///
    /// # Safety
    ///
    /// `result`, `buf`, and `errnop` must be valid pointers. `buf` must be at
    /// least `buflen` bytes.
    pub(crate) unsafe fn fill_group_buf(
        grp: &sssd_oidc::model::Group,
        result: *mut group,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus {
        let mut offset: usize = 0;

        // Write gr_name
        let gr_name = match unsafe { write_str(buf, buflen, &mut offset, &grp.name) } {
            Some(p) => p,
            None => return buffer_too_small(errnop),
        };
        // Write gr_passwd
        let gr_passwd = match unsafe { write_str(buf, buflen, &mut offset, "x") } {
            Some(p) => p,
            None => return buffer_too_small(errnop),
        };

        // Write each member name string into the buffer
        let mut member_ptrs: Vec<*mut c_char> = Vec::with_capacity(grp.members.len());
        for member in &grp.members {
            match unsafe { write_str(buf, buflen, &mut offset, member) } {
                Some(p) => member_ptrs.push(p),
                None => return buffer_too_small(errnop),
            }
        }

        // Align offset to pointer alignment
        let ptr_align = std::mem::align_of::<*mut c_char>();
        let misalign = offset % ptr_align;
        if misalign != 0 {
            offset += ptr_align - misalign;
        }

        // Check we have room for (members.len() + 1) pointers (including NULL sentinel)
        let ptrs_needed = (member_ptrs.len() + 1) * std::mem::size_of::<*mut c_char>();
        if offset + ptrs_needed > buflen {
            return buffer_too_small(errnop);
        }

        // Write the pointer array into the buffer
        let gr_mem = unsafe { buf.add(offset) } as *mut *mut c_char;
        for (i, ptr) in member_ptrs.iter().enumerate() {
            unsafe {
                gr_mem.add(i).write_unaligned(*ptr);
            }
        }
        // NULL sentinel
        unsafe {
            gr_mem
                .add(member_ptrs.len())
                .write_unaligned(std::ptr::null_mut());
        }

        unsafe {
            (*result).gr_name = gr_name;
            (*result).gr_passwd = gr_passwd;
            (*result).gr_gid = grp.gid;
            (*result).gr_mem = gr_mem;
            *errnop = 0;
        }

        NssStatus::Success
    }

    fn buffer_too_small(errnop: *mut c_int) -> NssStatus {
        unsafe {
            *errnop = ERANGE;
        }
        NssStatus::TryAgain
    }
}
