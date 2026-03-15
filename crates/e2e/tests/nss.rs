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

/// Active user passes check_user_active.
#[tokio::test(flavor = "multi_thread")]
async fn active_user_passes_acct_mgmt() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let active = tokio::task::spawn_blocking(move || svc.check_user_active("alice"))
        .await
        .unwrap()
        .unwrap();
    assert!(active);
}

/// Inactive user (SCIM active=false) is denied by check_user_active.
#[tokio::test(flavor = "multi_thread")]
async fn inactive_user_denied_by_acct_mgmt() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let active = tokio::task::spawn_blocking(move || svc.check_user_active("disabled_bob"))
        .await
        .unwrap()
        .unwrap();
    assert!(!active);
}

/// When SCIM is unreachable, cached user passes (assumed active).
#[tokio::test(flavor = "multi_thread")]
async fn acct_mgmt_falls_back_to_cache_on_scim_error() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();

    // First, look up alice to populate cache
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let active = tokio::task::spawn_blocking(move || {
        // Populate cache
        let _ = svc.lookup_user_by_name("alice").unwrap();
        // Now create a service pointing at a dead URL to simulate SCIM outage
        let (_config_file, config) = test_config("http://127.0.0.1:1", "http://127.0.0.1:1");
        let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
        // Re-use the same cache (in-memory won't work across services, but the
        // test_config uses ":memory:" which creates a new DB. We need a shared cache.)
        // For this test, we verify the code path by checking that a user we just
        // cached in the first service can be checked. Since each service gets its
        // own in-memory cache, we verify the logic differently: we pre-populate
        // the cache and check.
        let cache = Cache::open_in_memory().unwrap();
        let user = sssd_oidc::model::User {
            external_id: "user-uuid-alice-001".into(),
            name: "alice".into(),
            uid: 200_000,
            gid: 200_000,
            gecos: "Alice Smith".into(),
            home: "/home/alice".into(),
            shell: "/bin/bash".into(),
            active: true,
        };
        cache.store_user(&user).unwrap();
        let svc2 = Service::new(config, scim, cache);
        std::mem::forget(_config_file);
        svc2.check_user_active("alice").unwrap()
    })
    .await
    .unwrap();

    assert!(active);
}

/// Health check: SCIM endpoint is reachable.
#[tokio::test(flavor = "multi_thread")]
async fn is_online_returns_true_when_scim_reachable() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let online = tokio::task::spawn_blocking(move || svc.is_online())
        .await
        .unwrap();
    assert!(online);
}

/// Health check: SCIM endpoint unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn is_online_returns_false_when_scim_unreachable() {
    let (_config_file, config) = test_config("http://127.0.0.1:1", "http://127.0.0.1:1");
    let svc = tokio::task::spawn_blocking(move || {
        let scim = ScimClient::new(&config.scim.base_url, &config.scim.bearer_token);
        let cache = Cache::open_in_memory().unwrap();
        Service::new(config, scim, cache)
    })
    .await
    .unwrap();

    let online = tokio::task::spawn_blocking(move || svc.is_online())
        .await
        .unwrap();
    assert!(!online);
}

/// initgroups: look up supplementary groups for a user.
#[tokio::test(flavor = "multi_thread")]
async fn initgroups_returns_supplementary_gids() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let gids = tokio::task::spawn_blocking(move || svc.lookup_groups_for_user("alice"))
        .await
        .unwrap()
        .unwrap();

    assert!(!gids.is_empty());
    assert!(gids.iter().all(|&g| g >= 200_000 && g < 400_000));
}

/// initgroups returns empty for nonexistent user.
#[tokio::test(flavor = "multi_thread")]
async fn initgroups_returns_empty_for_nonexistent_user() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let gids = tokio::task::spawn_blocking(move || svc.lookup_groups_for_user("nonexistent"))
        .await
        .unwrap()
        .unwrap();

    assert!(gids.is_empty());
}

/// Enumerate all users via SCIM pagination.
#[tokio::test(flavor = "multi_thread")]
async fn enumerate_users_via_scim_pagination() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let users = tokio::task::spawn_blocking(move || svc.list_all_users())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(users.len(), 2);
    let names: Vec<&str> = users.iter().map(|u| u.name.as_str()).collect();
    assert!(names.contains(&"alice"));
    assert!(names.contains(&"disabled_bob"));
}

/// Enumerate all groups via SCIM pagination.
#[tokio::test(flavor = "multi_thread")]
async fn enumerate_groups_via_scim_pagination() {
    let idp = MockIdp::start().await;
    let base = idp.base_url();
    let svc = tokio::task::spawn_blocking({
        let base = base.clone();
        move || make_service(&base, &base)
    })
    .await
    .unwrap();

    let groups = tokio::task::spawn_blocking(move || svc.list_all_groups())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "engineering");
}
