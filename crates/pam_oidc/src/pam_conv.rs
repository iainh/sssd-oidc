use libc::{c_char, c_int, c_void, free};
use std::ffi::{CStr, CString};

use crate::ffi::PamHandle;

/// PAM message styles (from <security/pam_appl.h>).
const PAM_TEXT_INFO: c_int = 4;

/// PAM constants.
const PAM_CONV: c_int = 5;

/// PAM return codes.
const PAM_SUCCESS: c_int = 0;

/// PAM conversation message.
#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

/// PAM conversation response.
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

/// PAM conversation structure.
#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

unsafe extern "C" {
    fn pam_get_item(pamh: *mut PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
}

/// Get the PAM username.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
pub unsafe fn get_pam_user(pamh: *mut PamHandle) -> Result<String, c_int> {
    let mut user_ptr: *const c_char = std::ptr::null();
    let ret = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if ret != PAM_SUCCESS || user_ptr.is_null() {
        return Err(ret);
    }
    let user = unsafe { CStr::from_ptr(user_ptr) }
        .to_str()
        .map_err(|_| ret)?
        .to_string();
    Ok(user)
}

/// Send an info message to the user via PAM conversation.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
pub unsafe fn pam_info(pamh: *mut PamHandle, msg: &str) -> c_int {
    let conv = match unsafe { get_pam_conv(pamh) } {
        Some(c) => c,
        None => return PAM_SUCCESS, // silently succeed if no conversation
    };

    let c_msg = match CString::new(msg) {
        Ok(s) => s,
        Err(_) => return PAM_SUCCESS,
    };

    let pam_msg = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: c_msg.as_ptr(),
    };

    let mut msg_ptr: *const PamMessage = &pam_msg;
    let mut resp: *mut PamResponse = std::ptr::null_mut();

    let conv_fn = match conv.conv {
        Some(f) => f,
        None => return PAM_SUCCESS,
    };

    let ret = unsafe { conv_fn(1, &mut msg_ptr, &mut resp, conv.appdata_ptr) };

    // Free any response allocated by the conversation function
    if !resp.is_null() {
        unsafe {
            if !(*resp).resp.is_null() {
                free((*resp).resp as *mut c_void);
            }
            free(resp as *mut c_void);
        }
    }

    ret
}

/// Get the PAM conversation structure.
///
/// # Safety
///
/// `pamh` must be a valid PAM handle.
unsafe fn get_pam_conv(pamh: *mut PamHandle) -> Option<&'static PamConv> {
    let mut item: *const c_void = std::ptr::null();
    let ret = unsafe { pam_get_item(pamh, PAM_CONV, &mut item) };
    if ret != PAM_SUCCESS || item.is_null() {
        return None;
    }
    Some(unsafe { &*(item as *const PamConv) })
}
