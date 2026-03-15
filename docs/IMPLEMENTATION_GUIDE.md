# sssd-oidc Implementation Guide

This guide describes every feature needed to complete the sssd-oidc project,
how to test each one, and how to know when it's done. Features are ordered by
dependency — complete them top-to-bottom. Each feature is a standalone unit of
work suitable for an LLM coding agent.

The end-goal acceptance test is: a Podman container running SSSD in proxy mode
can resolve a user via `getent passwd <name>` and authenticate via
`pamtester` against a test OIDC provider (Keycloak in a sidecar container).

---

## Current State (what's already done)

| Component | Status | Location |
|---|---|---|
| Config loading (TOML) | ✅ Complete | `src/config.rs` |
| SCIM 2.0 client (user/group lookup) | ✅ Complete | `src/scim.rs` |
| UID/GID deterministic mapping (murmur3) | ✅ Complete | `src/mapping.rs` |
| SQLite cache (store/reverse lookup) | ✅ Complete | `src/cache.rs` |
| Domain model (User, Group) | ✅ Complete | `src/model.rs` |
| Service façade (SCIM → model + cache) | ✅ Complete | `src/service.rs` |
| NSS passwd FFI (Feature 1) | ✅ Complete | `crates/nss_oidc/src/passwd.rs`, `state.rs` |
| NSS group FFI (Feature 2) | ✅ Complete | `crates/nss_oidc/src/group.rs` |
| NSS FFI exports (symbol stubs) | ✅ Stubs only | `crates/nss_oidc/src/` |
| PAM FFI exports (symbol stubs) | ✅ Stubs only | `crates/pam_oidc/src/` |
| E2E test infra (wiremock mock IdP) | ✅ Complete | `crates/e2e/tests/` |
| OIDC Discovery (Feature 3) | ✅ Complete | `src/oidc.rs` |
| OIDC Device Code (Feature 4) | ✅ Complete | `src/oidc.rs` |
| PAM authenticate (Feature 5) | ✅ Complete | `crates/pam_oidc/src/ffi.rs`, `pam_conv.rs` |
| Access control (Feature 6) | ✅ Complete | `src/service.rs`, `crates/pam_oidc/src/ffi.rs` |
| All existing tests passing | ✅ 29 tests pass | `cargo test --workspace` |

---

## Build & Verify

```sh
# Full workspace check (format, clippy, test)
cargo fmt --check
cargo clippy --workspace
cargo test --workspace

# Cross-compile for Linux (needed for NSS/PAM .so files)
# Use a Linux container or cross-compilation toolchain
cargo build --workspace --release --target x86_64-unknown-linux-gnu
```

---

## Feature 1: Wire NSS passwd functions to the Service layer

**Goal**: `_nss_oidc_getpwnam_r` and `_nss_oidc_getpwuid_r` call
`Service::lookup_user_by_name` / `lookup_user_by_uid` and write results into
the C `struct passwd`.

### What to implement

1. **`crates/nss_oidc/src/passwd.rs`** — Replace the TODO stubs in
   `fill_passwd::by_name` and `fill_passwd::by_uid`:
   - Load config via `Config::load()` (cache the `Service` in a
     `std::sync::OnceLock<Service>` at module level so it's initialized once)
   - Call the appropriate `Service::lookup_*` method
   - On `Some(user)`: write `pw_name`, `pw_passwd` (`"x"`), `pw_uid`,
     `pw_gid`, `pw_gecos`, `pw_dir`, `pw_shell` into the provided buffer
     using the existing `write_str` helper, and set `*result` fields
   - On `None`: return `NssStatus::NotFound`
   - On buffer too small: return `NssStatus::TryAgain` with `*errnop = ERANGE`
   - On service error: return `NssStatus::Unavail`
2. **`crates/nss_oidc/src/lib.rs`** or a new `state.rs` — Add a
   `OnceLock<Service>` singleton with a helper function `get_service() -> &Service`
   that initializes config + SCIM client + cache on first call.

### Conventions

- `unsafe` code is confined to `passwd.rs` and `ffi.rs`
- Use `reqwest::blocking` (NSS callbacks are synchronous C calls)
- Convert `*const c_char` name to `&str` with `CStr::from_ptr().to_str()`
- The `write_str` helper already exists in `passwd.rs` — use it

### How to test

**Unit tests** (in `crates/nss_oidc/src/passwd.rs`):
- Test `write_str` writes a NUL-terminated string and advances the offset
- Test `write_str` returns `None` when buffer is too small

**E2E tests** (in `crates/e2e/tests/nss.rs`) — add:
```rust
#[tokio::test]
async fn nss_getpwnam_r_fills_passwd_struct() {
    // Start MockIdp, set SSSD_OIDC_CONFIG env var to temp config,
    // call _nss_oidc_getpwnam_r("alice", ...) via FFI,
    // verify the passwd struct fields match expected values.
}

#[tokio::test]
async fn nss_getpwnam_r_returns_notfound_for_unknown_user() {
    // Call _nss_oidc_getpwnam_r("nonexistent", ...) → NssStatus::NotFound
}

#[tokio::test]
async fn nss_getpwuid_r_after_name_lookup() {
    // First call getpwnam_r("alice") to populate cache,
    // then call getpwuid_r(alice_uid) and verify it returns the same user.
}

#[tokio::test]
async fn nss_getpwnam_r_returns_tryagain_on_small_buffer() {
    // Call with a 1-byte buffer → NssStatus::TryAgain, errno == ERANGE
}
```

### Done when

- [x] `cargo test --workspace` passes with the new tests
- [x] `cargo clippy --workspace` has no errors (warnings on unused enum
      variants are acceptable for now)
- [x] FFI call `_nss_oidc_getpwnam_r("alice")` fills a valid `struct passwd`
      with `pw_name="alice"`, `pw_uid` in range [200000, 400000)

---

## Feature 2: Wire NSS group functions to the Service layer

**Goal**: `_nss_oidc_getgrnam_r` and `_nss_oidc_getgrgid_r` fill
`struct group` from SCIM data.

### What to implement

1. **`crates/nss_oidc/src/group.rs`** — Replace the TODO stubs:
   - Use the same `OnceLock<Service>` from Feature 1
   - Call `Service::lookup_group_by_name` / `lookup_group_by_gid`
   - Write `gr_name`, `gr_passwd` (`"x"`), `gr_gid`, `gr_mem` (NULL-
     terminated array of member name C strings) into the buffer
   - Handle not-found, buffer-too-small, and service errors

### Writing `gr_mem`

`struct group.gr_mem` is a `*mut *mut c_char` — a NULL-terminated array of
pointers to C strings, all packed into the caller-provided buffer. Layout:

```
buf: [ "alice\0" | "bob\0" | ptr→alice | ptr→bob | NULL ]
                              ^^^^^^^^^^^^^^^^^^^^^^^^^^
                              gr_mem points here
```

Steps:
1. Write each member name string into the buffer using `write_str`
2. Align the offset to pointer alignment (`std::mem::align_of::<*mut c_char>()`)
3. Write the pointer array: one `*mut c_char` per member, then a NULL sentinel
4. Set `result.gr_mem` to the start of the pointer array

### How to test

**E2E tests** (in `crates/e2e/tests/nss.rs`):
```rust
#[tokio::test]
async fn nss_getgrnam_r_fills_group_struct() {
    // Call _nss_oidc_getgrnam_r("engineering", ...)
    // Verify gr_name == "engineering", gr_gid in range, gr_mem contains "alice"
}

#[tokio::test]
async fn nss_getgrnam_r_returns_notfound_for_unknown_group() {
    // _nss_oidc_getgrnam_r("nonexistent") → NssStatus::NotFound
}

#[tokio::test]
async fn nss_getgrgid_r_after_name_lookup() {
    // First lookup by name to populate cache, then lookup by GID
}
```

### Done when

- [x] `cargo test --workspace` passes with new group tests
- [x] FFI call `_nss_oidc_getgrnam_r("engineering")` fills `struct group`
      with correct `gr_name`, `gr_gid`, and `gr_mem` member list

---

## Feature 3: OIDC Discovery Client

**Goal**: Fetch and cache OIDC endpoint URLs from
`{issuer}/.well-known/openid-configuration`.

### What to implement

1. **`src/oidc.rs`** (new file) — Add to `src/lib.rs` as `pub mod oidc`:
   ```rust
   pub struct OidcEndpoints {
       pub device_authorization_endpoint: String,
       pub token_endpoint: String,
       pub issuer: String,
   }

   pub struct OidcClient {
       http: reqwest::blocking::Client,
       endpoints: OidcEndpoints,
       client_id: String,
       client_secret: Option<String>,
   }

   impl OidcClient {
       /// Discover endpoints and create client.
       pub fn discover(issuer_url: &str, client_id: &str,
                       client_secret: Option<&str>) -> Result<Self, OidcError>;
   }
   ```

### How to test

**E2E test** (in `crates/e2e/tests/`):
```rust
#[tokio::test]
async fn oidc_discovery_parses_endpoints() {
    let idp = MockIdp::start().await;
    let client = spawn_blocking(move ||
        OidcClient::discover(&idp.base_url(), "test-client", None)
    ).await.unwrap().unwrap();
    assert!(client.endpoints().token_endpoint.contains("/token"));
    assert!(client.endpoints().device_authorization_endpoint.contains("/device"));
}
```

The mock IdP already serves `/.well-known/openid-configuration` — the mock
is already set up in `crates/e2e/tests/common/mock_idp.rs`.

### Done when

- [x] `OidcClient::discover()` fetches and parses the discovery document
- [x] E2E test confirms correct endpoint extraction from the mock server

---

## Feature 4: OIDC Device Authorization Grant (RFC 8628)

**Goal**: Implement the device code flow for PAM authentication.

### What to implement

1. **`src/oidc.rs`** — Add two methods to `OidcClient`:
   ```rust
   pub struct DeviceAuthResponse {
       pub device_code: String,
       pub user_code: String,
       pub verification_uri: String,
       pub verification_uri_complete: Option<String>,
       pub expires_in: u64,
       pub interval: u64,
   }

   pub struct TokenResponse {
       pub access_token: String,
       pub id_token: Option<String>,
       pub token_type: String,
   }

   impl OidcClient {
       /// Step 1: Request a device code.
       /// POST to device_authorization_endpoint with client_id + scope.
       pub fn request_device_code(&self, scope: &str)
           -> Result<DeviceAuthResponse, OidcError>;

       /// Step 2: Poll for token until user completes browser auth.
       /// POST to token_endpoint with grant_type=urn:ietf:params:oauth:grant-type:device_code
       /// Polls at the interval specified in DeviceAuthResponse.
       /// Returns Err(OidcError::AuthorizationPending) while waiting,
       /// Err(OidcError::SlowDown) if polling too fast,
       /// Err(OidcError::ExpiredToken) if the code expired.
       pub fn poll_for_token(&self, device_code: &str)
           -> Result<TokenResponse, OidcError>;

       /// Combined: request code, display message, poll until done.
       /// `display_fn` is called with the user_code and verification_uri
       /// so the PAM module can show them to the user.
       pub fn authenticate_device_flow<F>(&self, scope: &str, display_fn: F)
           -> Result<TokenResponse, OidcError>
       where F: FnOnce(&str, &str);
   }
   ```

### How to test

**E2E tests** — extend `MockIdp` with device code endpoints:
```rust
// Add to mock_idp.rs:
// POST /device → returns device_code, user_code, verification_uri
// POST /token with grant_type=device_code:
//   - First call: 400 {"error": "authorization_pending"}
//   - Second call: 200 {access_token, id_token}

#[tokio::test]
async fn device_code_flow_succeeds_after_pending() {
    let idp = MockIdp::start().await;
    // mock /device to return a device code
    // mock /token to return authorization_pending once, then succeed
    let client = OidcClient::discover(...).unwrap();
    let result = client.authenticate_device_flow("openid", |code, uri| {
        // verify code and uri are non-empty
    });
    assert!(result.is_ok());
}

#[tokio::test]
async fn device_code_flow_handles_expired_token() {
    // mock /token to always return "expired_token" error
    // verify OidcError::ExpiredToken is returned
}
```

### Done when

- [x] `request_device_code()` POSTs to the device authorization endpoint and
      parses the response
- [x] `poll_for_token()` handles `authorization_pending`, `slow_down`, and
      success responses correctly
- [x] E2E tests pass with wiremock simulating the multi-step flow

---

## Feature 5: Wire PAM authenticate to OIDC device flow

**Goal**: `pam_sm_authenticate` initiates the device code flow, displays the
verification URI/code to the user via PAM conversation, and returns
`PAM_SUCCESS` on successful authentication.

### What to implement

1. **`crates/pam_oidc/src/ffi.rs`** — Implement `pam_sm_authenticate`:
   - Extract the username from PAM via `pam_get_user()` (use `extern "C"` to
     call into libpam)
   - Load config, create `OidcClient` via discovery
   - Call `authenticate_device_flow()`, using `pam_info()` / PAM conversation
     to display the verification URI and user code
   - On success: verify the token's `sub` or `preferred_username` claim
     matches the PAM username
   - Return `PAM_SUCCESS` or `PAM_AUTH_ERR`
2. **`crates/pam_oidc/src/pam_conv.rs`** (new) — Safe wrappers for PAM
   conversation functions:
   ```rust
   /// Send an info message to the user via PAM conversation.
   pub unsafe fn pam_info(pamh: *mut PamHandle, msg: &str) -> c_int;
   /// Get the PAM username.
   pub unsafe fn pam_get_user(pamh: *mut PamHandle) -> Result<String, c_int>;
   ```

### PAM conversation for device code display

The PAM module must display the verification URI and user code to the user.
Use `PAM_TEXT_INFO` message type via the PAM conversation function:

```
To sign in, visit: https://idp.example.com/device
Enter code: ABCD-1234
Waiting for authentication...
```

### How to test

**Unit test**: Verify that `pam_sm_setcred` and `pam_sm_acct_mgmt` continue
to return `PAM_SUCCESS`.

**E2E test** (in `crates/e2e/tests/pam.rs`):

PAM conversation testing is difficult without a real PAM stack. The primary
test strategy is:
1. Test the OIDC flow separately (Feature 4 tests)
2. Test PAM symbol exports exist (already done)
3. Integration test in the container (Feature 9)

Add a service-level test:
```rust
#[tokio::test]
async fn pam_auth_flow_with_mock_idp() {
    // Test the OidcClient device flow with mock endpoints,
    // verifying the flow works end-to-end at the library level.
    // The actual PAM conversation is tested in the container E2E.
}
```

### Done when

- [x] `pam_sm_authenticate` compiles and calls the OIDC device flow
- [x] `cargo test --workspace` passes
- [ ] The container integration test (Feature 9) can authenticate a user

---

## Feature 6: Access control — SCIM `active` flag

**Goal**: `pam_sm_acct_mgmt` checks whether the SCIM user is `active` and
returns `PAM_PERM_DENIED` if not.

### What to implement

1. **`src/service.rs`** — Add `check_user_active(name: &str) -> Result<bool>`:
   - SCIM lookup the user, check the `active` field
   - Fall back to cache if SCIM is unreachable (cached users are assumed
     active unless explicitly marked inactive)
2. **`crates/pam_oidc/src/ffi.rs`** — In `pam_sm_acct_mgmt`:
   - Get the PAM username
   - Call `service.check_user_active(name)`
   - Return `PAM_SUCCESS` if active, `PAM_PERM_DENIED` if inactive,
     `PAM_AUTHINFO_UNAVAIL` on error

### How to test

**E2E tests**:
```rust
#[tokio::test]
async fn active_user_passes_acct_mgmt() {
    // Mock SCIM returns user with active=true
    // service.check_user_active("alice") returns true
}

#[tokio::test]
async fn inactive_user_denied_by_acct_mgmt() {
    // Add a mock user "disabled_bob" with active=false
    // service.check_user_active("disabled_bob") returns false
}

#[tokio::test]
async fn acct_mgmt_falls_back_to_cache_on_scim_error() {
    // Mock SCIM returns 500
    // Previously cached user should still pass (assumed active)
}
```

### Done when

- [x] Inactive users (SCIM `active: false`) are denied by `pam_sm_acct_mgmt`
- [x] Active users pass
- [x] SCIM outage falls back to cache gracefully

---

## Feature 7: NSS Enumeration (`setpwent` / `getpwent` / `endpwent`)

**Goal**: Support SSSD's enumeration mode (`enumerate = true`) by listing all
users/groups via paginated SCIM requests.

### What to implement

1. **`src/scim.rs`** — Add paginated list methods:
   ```rust
   impl ScimClient {
       /// List all users, paginating via startIndex + count.
       pub fn list_users(&self) -> Result<Vec<ScimUser>, ScimError>;
       /// List all groups, paginating via startIndex + count.
       pub fn list_groups(&self) -> Result<Vec<ScimGroup>, ScimError>;
   }
   ```
2. **`src/service.rs`** — Add `list_all_users()` and `list_all_groups()` that
   call SCIM list, convert to models, and cache each entry.
3. **`crates/nss_oidc/src/ffi.rs`** — Add NSS enumeration exports:
   ```rust
   #[unsafe(no_mangle)]
   pub unsafe extern "C" fn _nss_oidc_setpwent() -> NssStatus;
   #[unsafe(no_mangle)]
   pub unsafe extern "C" fn _nss_oidc_getpwent_r(...) -> NssStatus;
   #[unsafe(no_mangle)]
   pub unsafe extern "C" fn _nss_oidc_endpwent() -> NssStatus;

   // Same for groups: setgrent, getgrent_r, endgrent
   ```
4. **Enumeration state** — Use a `Mutex<Option<Vec<User>>>` to hold the
   current enumeration list. `setpwent` fetches all users, `getpwent_r`
   returns the next one, `endpwent` clears the state.

### How to test

**E2E tests** — Add paginated SCIM list mocks to `MockIdp`:
```rust
#[tokio::test]
async fn enumerate_users_via_scim_pagination() {
    // Mock GET /Users (no filter) returns paginated results
    // service.list_all_users() returns all users
}

#[tokio::test]
async fn setpwent_getpwent_endpwent_cycle() {
    // Call setpwent(), then getpwent_r() until NotFound, then endpwent()
    // Verify all mock users are returned
}
```

### Done when

- [ ] `getent passwd` in a container lists all SCIM users
- [ ] Pagination handles `totalResults > count` responses
- [ ] `endpwent` cleans up enumeration state

---

## Feature 8: Containerized Build (Podman)

**Goal**: Create a multi-stage Containerfile that cross-compiles the Rust
workspace on any host and produces a minimal Linux image with the NSS/PAM
modules installed.

### What to create

1. **`Containerfile`** (project root):
   ```dockerfile
   # Stage 1: Build
   FROM docker.io/library/rust:1.85-bookworm AS builder
   RUN apt-get update && apt-get install -y libpam0g-dev
   WORKDIR /build
   COPY . .
   RUN cargo build --workspace --release

   # Stage 2: Runtime
   FROM docker.io/library/debian:bookworm-slim
   RUN apt-get update && apt-get install -y \
       sssd sssd-proxy libpam-runtime libpam-modules \
       && rm -rf /var/lib/apt/lists/*

   # Install NSS module
   COPY --from=builder /build/target/release/libnss_oidc.so \
        /usr/lib/x86_64-linux-gnu/libnss_oidc.so.2

   # Install PAM module
   COPY --from=builder /build/target/release/libpam_oidc.so \
        /usr/lib/x86_64-linux-gnu/security/pam_oidc.so

   # Configure NSS
   RUN sed -i 's/^passwd:.*/passwd: files oidc/' /etc/nsswitch.conf && \
       sed -i 's/^group:.*/group: files oidc/' /etc/nsswitch.conf

   # PAM config for oidc service
   RUN echo "auth required pam_oidc.so" > /etc/pam.d/oidc && \
       echo "account required pam_oidc.so" >> /etc/pam.d/oidc

   # SSSD config
   COPY test/sssd.conf /etc/sssd/sssd.conf
   RUN chmod 600 /etc/sssd/sssd.conf

   # sssd-oidc config
   COPY test/config.toml /etc/sssd-oidc/config.toml

   # Cache directory
   RUN mkdir -p /var/lib/sssd-oidc

   CMD ["/usr/sbin/sssd", "-i", "--logger=stderr"]
   ```
2. **`test/sssd.conf`**:
   ```ini
   [sssd]
   services = nss, pam
   domains = oidc

   [domain/oidc]
   id_provider = proxy
   proxy_lib_name = oidc
   auth_provider = proxy
   proxy_pam_target = oidc
   entry_cache_timeout = 300

   [nss]
   default_shell = /bin/bash
   fallback_homedir = /home/%u
   ```
3. **`test/config.toml`** — Template with placeholders for the SCIM/OIDC
   URLs (filled at test time via env vars or sed).

### How to test

```sh
# Build the container
podman build -t sssd-oidc-test .

# Verify the .so files are installed correctly
podman run --rm sssd-oidc-test ls -la /usr/lib/x86_64-linux-gnu/libnss_oidc.so.2
podman run --rm sssd-oidc-test ls -la /usr/lib/x86_64-linux-gnu/security/pam_oidc.so

# Verify NSS module loads (even without a running SCIM server, getent
# should return "not found" rather than crashing)
podman run --rm sssd-oidc-test getent passwd testuser || true
```

### Done when

- [ ] `podman build -t sssd-oidc-test .` succeeds
- [ ] The container has `libnss_oidc.so.2` and `pam_oidc.so` installed in
      the correct paths
- [ ] `getent passwd <name>` does not crash (returns not found or the user)
- [ ] `nsswitch.conf` references `oidc`
- [ ] SSSD config is valid

---

## Feature 9: Keycloak Test IdP Container

**Goal**: Run Keycloak with SCIM support as a test OIDC provider alongside
the sssd-oidc container, with pre-provisioned test users.

### What to create

1. **`test/docker-compose.yml`** (or `test/podman-compose.yml`):
   ```yaml
   version: "3"
   services:
     keycloak:
       image: quay.io/keycloak/keycloak:26.2
       environment:
         KC_BOOTSTRAP_ADMIN_USERNAME: admin
         KC_BOOTSTRAP_ADMIN_PASSWORD: admin
         KC_HTTP_ENABLED: "true"
         KC_HOSTNAME_STRICT: "false"
       command: start-dev
       ports:
         - "8080:8080"

     sssd-oidc:
       build: ..
       depends_on:
         - keycloak
       environment:
         SSSD_OIDC_CONFIG: /etc/sssd-oidc/config.toml
       volumes:
         - ./config-keycloak.toml:/etc/sssd-oidc/config.toml:ro
   ```
2. **`test/setup-keycloak.sh`** — Script that uses the Keycloak Admin REST
   API to:
   - Create a realm (`test-realm`)
   - Install the `scim-for-keycloak` plugin (or use Keycloak's built-in SCIM
     if available in the version used)
   - Create an OIDC client with device code flow enabled
   - Create test users (`alice`, `bob`) and groups (`engineering`)
   - Enable the SCIM endpoint
3. **`test/config-keycloak.toml`**:
   ```toml
   [scim]
   base_url = "http://keycloak:8080/realms/test-realm/scim/v2"
   bearer_token = "<admin-token>"

   [oidc]
   issuer_url = "http://keycloak:8080/realms/test-realm"
   client_id = "sssd-oidc-test"
   ```

### Alternative: Simpler mock IdP for CI

If Keycloak + SCIM plugin is too heavy, create a lightweight mock IdP
container using the existing wiremock test fixtures:

1. **`test/mock-idp/`** — A small Rust binary that runs a wiremock server
   with the same mocks from `crates/e2e/tests/common/mock_idp.rs`, plus
   device code flow endpoints that auto-approve after a delay.
2. This is simpler for CI and doesn't require Keycloak setup.

### How to test

```sh
cd test
podman-compose up -d
# Wait for Keycloak to be ready
./setup-keycloak.sh
# Test NSS resolution
podman exec sssd-oidc getent passwd alice
# Test PAM authentication (requires pamtester)
podman exec sssd-oidc pamtester oidc alice authenticate
```

### Done when

- [ ] `podman-compose up` starts both containers
- [ ] Keycloak has test users provisioned with SCIM enabled
- [ ] `getent passwd alice` inside the sssd-oidc container returns a valid
      passwd entry
- [ ] `getent group engineering` returns the group with alice as a member

---

## Feature 10: End-to-End Automated Test Script

**Goal**: A single script that builds everything, starts containers, runs
tests, and reports pass/fail. This is the final acceptance test.

### What to create

1. **`test/e2e-container-test.sh`**:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail

   echo "=== Building sssd-oidc container ==="
   podman build -t sssd-oidc-test -f Containerfile .

   echo "=== Starting test environment ==="
   cd test
   podman-compose up -d --build
   # Wait for services
   ./wait-for-ready.sh

   echo "=== Provisioning test IdP ==="
   ./setup-keycloak.sh

   echo "=== Test 1: NSS user lookup by name ==="
   RESULT=$(podman exec sssd-oidc-test getent passwd alice)
   echo "$RESULT"
   echo "$RESULT" | grep -q "alice" || { echo "FAIL: user alice not found"; exit 1; }

   echo "=== Test 2: NSS group lookup by name ==="
   RESULT=$(podman exec sssd-oidc-test getent group engineering)
   echo "$RESULT"
   echo "$RESULT" | grep -q "engineering" || { echo "FAIL: group not found"; exit 1; }

   echo "=== Test 3: NSS user lookup by UID ==="
   # Extract UID from previous getent output, then look up by UID
   UID_VAL=$(echo "$RESULT" | cut -d: -f3)
   podman exec sssd-oidc-test getent passwd "$UID_VAL" | grep -q "alice"

   echo "=== Test 4: PAM authentication ==="
   # This test requires the mock IdP to auto-approve device codes
   podman exec sssd-oidc-test pamtester oidc alice authenticate \
     || { echo "FAIL: PAM auth failed"; exit 1; }

   echo "=== Test 5: Inactive user denied ==="
   # disabled_bob should be denied by pam_sm_acct_mgmt
   ! podman exec sssd-oidc-test pamtester oidc disabled_bob acct_mgmt \
     || { echo "FAIL: inactive user should be denied"; exit 1; }

   echo "=== Test 6: Offline fallback ==="
   # Stop the IdP, verify cached users still resolve
   podman stop test-keycloak
   podman exec sssd-oidc-test getent passwd alice \
     || { echo "FAIL: offline fallback failed"; exit 1; }

   echo "=== Cleanup ==="
   podman-compose down

   echo "=== ALL TESTS PASSED ==="
   ```

2. **`test/wait-for-ready.sh`** — Polls Keycloak health endpoint until ready.

### How to test

```sh
./test/e2e-container-test.sh
```

### Done when

- [ ] Script runs unattended and exits 0 on success
- [ ] All 6 test categories pass:
  1. NSS user lookup by name (`getent passwd alice`)
  2. NSS group lookup by name (`getent group engineering`)
  3. NSS user lookup by UID (reverse lookup)
  4. PAM authentication (device code flow)
  5. Inactive user denied
  6. Offline cache fallback
- [ ] Script exits non-zero on any failure with a clear error message

---

## Dependency Graph

```
Feature 1 (NSS passwd)  ──┐
Feature 2 (NSS group)   ──┤
Feature 3 (OIDC discovery)─┼── Feature 8 (Container build)
Feature 4 (Device code) ──┤       │
Feature 5 (PAM auth)    ──┤       ├── Feature 9 (Test IdP)
Feature 6 (Access ctrl) ──┘       │       │
Feature 7 (Enumeration) ──────────┘       │
                                          │
                                   Feature 10 (E2E script)
```

Features 1–7 can be developed in parallel (1+2 share NSS state, 3→4→5 are
sequential, 6 is independent, 7 is independent). Feature 8 requires at least
Features 1–2 to be useful. Feature 9 requires Feature 8. Feature 10 requires
all others.

---

## Conventions for All Features

- **Rust edition 2024**, MSRV 1.85
- `thiserror` for error types, `serde` + `toml` for config
- `reqwest::blocking` for all HTTP (NSS/PAM are synchronous C calls)
- `rusqlite` (bundled feature) for SQLite cache
- `unsafe` code confined to FFI boundary files (`ffi.rs`, `passwd.rs`, `group.rs`)
- Use `#[unsafe(no_mangle)]` (Rust 2024 syntax) for exported symbols
- Run `cargo fmt`, `cargo clippy --workspace`, `cargo test --workspace`
  before considering any feature complete
- E2E tests use `wiremock` + `tokio::test` with `spawn_blocking` for sync calls
- Never use `std::collections::hash_map::DefaultHasher` for UID/GID mapping
  — always use `murmur3` (seed 0)
