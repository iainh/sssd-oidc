mod common;

use common::mock_idp::MockIdp;
use common::test_config;
use libc::ERANGE;
use std::ffi::CStr;
use std::ffi::CString;
use tokio::sync::OnceCell;

/// Extracted passwd fields as safe, owned types.
#[derive(Debug)]
struct PasswdResult {
    name: String,
    passwd: String,
    uid: u32,
    gid: u32,
    gecos: String,
    dir: String,
    shell: String,
}

static INIT: OnceCell<()> = OnceCell::const_new();

/// Initialise the mock IdP and set SSSD_OIDC_CONFIG. Must be called before
/// any FFI function.
async fn ensure_init() {
    INIT.get_or_init(|| async {
        let idp = MockIdp::start().await;
        let base_url = idp.base_url();
        let (config_file, _config) = test_config(&base_url, &base_url);
        // SAFETY: we are in test code; init runs once before any concurrent access
        unsafe {
            std::env::set_var("SSSD_OIDC_CONFIG", config_file.path());
        }
        // Leak both so they live for the process lifetime
        std::mem::forget(idp);
        std::mem::forget(config_file);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getpwnam_r_fills_passwd_struct() {
    ensure_init().await;

    let (status, errnop, pw) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("alice").unwrap();
        let mut result: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 1024];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getpwnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };

        let pw = PasswdResult {
            name: unsafe { CStr::from_ptr(result.pw_name) }
                .to_str()
                .unwrap()
                .to_owned(),
            passwd: unsafe { CStr::from_ptr(result.pw_passwd) }
                .to_str()
                .unwrap()
                .to_owned(),
            uid: result.pw_uid,
            gid: result.pw_gid,
            gecos: unsafe { CStr::from_ptr(result.pw_gecos) }
                .to_str()
                .unwrap()
                .to_owned(),
            dir: unsafe { CStr::from_ptr(result.pw_dir) }
                .to_str()
                .unwrap()
                .to_owned(),
            shell: unsafe { CStr::from_ptr(result.pw_shell) }
                .to_str()
                .unwrap()
                .to_owned(),
        };

        (status, errnop, pw)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
    assert_eq!(errnop, 0);
    assert_eq!(pw.name, "alice");
    assert_eq!(pw.passwd, "x");
    assert!(pw.uid >= 200_000 && pw.uid < 400_000);
    assert!(pw.gid >= 200_000 && pw.gid < 400_000);
    assert_eq!(pw.gecos, "Alice Smith");
    assert_eq!(pw.dir, "/home/alice");
    assert_eq!(pw.shell, "/bin/bash");
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getpwnam_r_returns_notfound_for_unknown_user() {
    ensure_init().await;

    let (status, errnop) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("nonexistent").unwrap();
        let mut result: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 1024];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getpwnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };
        (status, errnop)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::NotFound);
    assert_eq!(errnop, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getpwuid_r_after_name_lookup() {
    ensure_init().await;

    let (name, uid) = tokio::task::spawn_blocking(|| {
        // First look up by name to populate cache
        let c_name = CString::new("alice").unwrap();
        let mut result: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 1024];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getpwnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };
        assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
        let uid = result.pw_uid;

        // Now look up by UID
        let mut result2: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf2 = [0i8; 1024];
        let mut errnop2: libc::c_int = 0;

        let status2 = unsafe {
            nss_oidc::ffi::_nss_oidc_getpwuid_r(
                uid,
                &mut result2,
                buf2.as_mut_ptr(),
                buf2.len(),
                &mut errnop2,
            )
        };
        assert_eq!(status2, nss_oidc::ffi::NssStatus::Success);

        let name = unsafe { CStr::from_ptr(result2.pw_name) }
            .to_str()
            .unwrap()
            .to_owned();
        (name, result2.pw_uid)
    })
    .await
    .unwrap();

    assert_eq!(name, "alice");
    assert!(uid >= 200_000 && uid < 400_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getpwnam_r_returns_tryagain_on_small_buffer() {
    ensure_init().await;

    let (status, errnop) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("alice").unwrap();
        let mut result: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 1]; // way too small
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getpwnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };
        (status, errnop)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::TryAgain);
    assert_eq!(errnop, ERANGE);
}

// --- initgroups FFI tests ---

#[tokio::test(flavor = "multi_thread")]
async fn nss_initgroups_dyn_returns_supplementary_gids() {
    ensure_init().await;

    let gids = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("alice").unwrap();
        let mut groups = vec![0u32; 64];
        let mut start: libc::c_long = 0;
        let mut size: libc::c_long = groups.len() as libc::c_long;
        let mut groups_ptr = groups.as_mut_ptr();
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_initgroups_dyn(
                c_name.as_ptr(),
                0, // primary gid (none to skip)
                &mut start,
                &mut size,
                &mut groups_ptr,
                0,
                &mut errnop,
            )
        };

        assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
        assert_eq!(errnop, 0);
        assert!(start > 0, "should have at least one supplementary group");

        let result: Vec<u32> = groups[..start as usize].to_vec();
        result
    })
    .await
    .unwrap();

    assert!(!gids.is_empty());
    assert!(gids.iter().all(|&g| g >= 200_000 && g < 400_000));
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_initgroups_dyn_returns_success_for_unknown_user() {
    ensure_init().await;

    let (status, start) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("nonexistent").unwrap();
        let mut groups = vec![0u32; 64];
        let mut start: libc::c_long = 0;
        let mut size: libc::c_long = groups.len() as libc::c_long;
        let mut groups_ptr = groups.as_mut_ptr();
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_initgroups_dyn(
                c_name.as_ptr(),
                0,
                &mut start,
                &mut size,
                &mut groups_ptr,
                0,
                &mut errnop,
            )
        };
        (status, start)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
    assert_eq!(start, 0);
}

// --- Group FFI tests ---

/// Extracted group fields as safe, owned types.
#[derive(Debug)]
struct GroupResult {
    name: String,
    passwd: String,
    gid: u32,
    members: Vec<String>,
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getgrnam_r_fills_group_struct() {
    ensure_init().await;

    let (status, errnop, grp) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("engineering").unwrap();
        let mut result: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 4096];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getgrnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };

        let grp = GroupResult {
            name: unsafe { CStr::from_ptr(result.gr_name) }
                .to_str()
                .unwrap()
                .to_owned(),
            passwd: unsafe { CStr::from_ptr(result.gr_passwd) }
                .to_str()
                .unwrap()
                .to_owned(),
            gid: result.gr_gid,
            members: {
                let mut members = Vec::new();
                let mut ptr = result.gr_mem;
                loop {
                    let entry = unsafe { ptr.read_unaligned() };
                    if entry.is_null() {
                        break;
                    }
                    members.push(
                        unsafe { CStr::from_ptr(entry) }
                            .to_str()
                            .unwrap()
                            .to_owned(),
                    );
                    ptr = unsafe { ptr.add(1) };
                }
                members
            },
        };

        (status, errnop, grp)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
    assert_eq!(errnop, 0);
    assert_eq!(grp.name, "engineering");
    assert_eq!(grp.passwd, "x");
    assert!(grp.gid >= 200_000 && grp.gid < 400_000);
    assert!(grp.members.contains(&"alice".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getgrnam_r_returns_notfound_for_unknown_group() {
    ensure_init().await;

    let (status, errnop) = tokio::task::spawn_blocking(|| {
        let c_name = CString::new("nonexistent").unwrap();
        let mut result: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 1024];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getgrnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };
        (status, errnop)
    })
    .await
    .unwrap();

    assert_eq!(status, nss_oidc::ffi::NssStatus::NotFound);
    assert_eq!(errnop, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn nss_getgrgid_r_after_name_lookup() {
    ensure_init().await;

    let (name, gid) = tokio::task::spawn_blocking(|| {
        // First look up by name to populate cache
        let c_name = CString::new("engineering").unwrap();
        let mut result: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = [0i8; 4096];
        let mut errnop: libc::c_int = 0;

        let status = unsafe {
            nss_oidc::ffi::_nss_oidc_getgrnam_r(
                c_name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errnop,
            )
        };
        assert_eq!(status, nss_oidc::ffi::NssStatus::Success);
        let gid = result.gr_gid;

        // Now look up by GID
        let mut result2: libc::group = unsafe { std::mem::zeroed() };
        let mut buf2 = [0i8; 4096];
        let mut errnop2: libc::c_int = 0;

        let status2 = unsafe {
            nss_oidc::ffi::_nss_oidc_getgrgid_r(
                gid,
                &mut result2,
                buf2.as_mut_ptr(),
                buf2.len(),
                &mut errnop2,
            )
        };
        assert_eq!(status2, nss_oidc::ffi::NssStatus::Success);

        let name = unsafe { CStr::from_ptr(result2.gr_name) }
            .to_str()
            .unwrap()
            .to_owned();
        (name, result2.gr_gid)
    })
    .await
    .unwrap();

    assert_eq!(name, "engineering");
    assert!(gid >= 200_000 && gid < 400_000);
}
