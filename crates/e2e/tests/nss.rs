mod common;

use common::mock_idp::MockIdp;
use common::test_config;
use sssd_oidc::cache::Cache;
use sssd_oidc::scim::ScimClient;
use sssd_oidc::service::Service;

fn make_service(scim_base_url: &str, oidc_issuer_url: &str) -> Service {
    let (_config_file, config) = test_config(scim_base_url, oidc_issuer_url);
    let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
    let cache = Cache::open_in_memory().unwrap();
    // Leak the config file handle so it stays alive for the duration of the test.
    std::mem::forget(_config_file);
    Service::new(config, scim, cache)
}

/// Verify that user lookup by name resolves via the mock SCIM server
/// and produces correct model fields with deterministic UID mapping.
#[tokio::test(flavor = "multi_thread")]
async fn lookup_user_by_name_via_scim() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let user = tokio::task::spawn_blocking(move || svc.lookup_user_by_name("alice"))
        .await
        .unwrap()
        .unwrap()
        .expect("alice should be found");

    assert_eq!(user.name, "alice");
    assert_eq!(user.gecos, "Alice Smith");
    assert_eq!(user.home, "/home/alice");
    assert_eq!(user.shell, "/bin/bash");
    assert!(user.uid >= 200_000 && user.uid < 400_000);
    assert!(user.gid >= 200_000 && user.gid < 400_000);
}

/// Verify that looking up a nonexistent user returns None.
#[tokio::test(flavor = "multi_thread")]
async fn lookup_nonexistent_user() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let user = tokio::task::spawn_blocking(move || svc.lookup_user_by_name("nonexistent"))
        .await
        .unwrap()
        .unwrap();
    assert!(user.is_none());
}

/// Verify that group lookup by name resolves via the mock SCIM server.
#[tokio::test(flavor = "multi_thread")]
async fn lookup_group_by_name_via_scim() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let group = tokio::task::spawn_blocking(move || svc.lookup_group_by_name("engineering"))
        .await
        .unwrap()
        .unwrap()
        .expect("engineering group should be found");

    assert_eq!(group.name, "engineering");
    assert!(group.gid >= 200_000 && group.gid < 400_000);
    assert_eq!(group.members, vec!["alice"]);
}

/// Verify that after a name lookup populates the cache,
/// a UID reverse lookup succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn uid_reverse_lookup_after_cache() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let (user_name, user_uid) = tokio::task::spawn_blocking(move || {
        let user = svc
            .lookup_user_by_name("alice")
            .unwrap()
            .expect("alice should be found");
        let uid = user.uid;

        let by_uid = svc
            .lookup_user_by_uid(uid)
            .unwrap()
            .expect("alice should be found by UID");

        (by_uid.name, by_uid.uid)
    })
    .await
    .unwrap();

    assert_eq!(user_name, "alice");
    assert!(user_uid >= 200_000 && user_uid < 400_000);
}

/// Verify deterministic mapping: same external_id always produces the same UID.
#[test]
fn deterministic_uid_mapping() {
    use sssd_oidc::mapping::id_to_uid;

    let uid1 = id_to_uid("user-uuid-alice-001", 200_000, 200_000);
    let uid2 = id_to_uid("user-uuid-alice-001", 200_000, 200_000);
    assert_eq!(uid1, uid2);
    assert!(uid1 >= 200_000 && uid1 < 400_000);
}
