mod common;

use common::mock_idp::MockIdp;

/// Verify that the PAM module exports are present and callable.
/// Full device-code-flow testing requires a PAM conversation callback,
/// which will be added once the auth flow is implemented.
#[tokio::test]
async fn pam_module_symbols_exist() {
    // Start the mock server (ensures the infra works).
    let _idp = MockIdp::start().await;

    // Verify the PAM FFI functions exist as callable symbols.
    // We call pam_sm_setcred with a null handle — it's a no-op stub
    // that returns PAM_SUCCESS without dereferencing the handle.
    let result = tokio::task::spawn_blocking(|| unsafe {
        pam_oidc::ffi::pam_sm_setcred(std::ptr::null_mut(), 0, 0, std::ptr::null())
    })
    .await
    .unwrap();
    assert_eq!(result, pam_oidc::ffi::PAM_SUCCESS);
}
