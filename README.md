# sssd-oidc

NSS and PAM modules (written in Rust) that let Linux resolve users/groups and
authenticate against any OIDC provider via SCIM 2.0 identity lookups.

Designed to run behind SSSD's `proxy` provider so that SSSD handles caching,
responders, and offline support while the modules handle the OIDC/SCIM protocol
work.

## Architecture

```
SSSD (proxy mode)
 ├─ id_provider = proxy  →  libnss_oidc.so  (NSS module, Rust/FFI)
 └─ auth_provider = proxy → pam_oidc.so     (PAM module, Rust/FFI)
                    │
                    ▼
          sssd-oidc (shared library)
           ├─ SCIM 2.0 client  (identity lookups)
           ├─ OIDC device code  (authentication)
           ├─ UID/GID mapping   (murmur3 hash)
           └─ SQLite cache      (reverse lookups)
```

### Workspace crates

| Crate | Output | Purpose |
|---|---|---|
| `sssd-oidc` (root) | `libsssd_oidc` | Shared library: config, SCIM client, OIDC client, UID mapping, cache, service façade |
| `crates/nss_oidc` | `libnss_oidc.so` | NSS module (`getpwnam_r`, `getpwuid_r`, `getgrnam_r`, `getgrgid_r`, enumeration, `initgroups_dyn`) |
| `crates/pam_oidc` | `pam_oidc.so` | PAM module (`pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`, `pam_sm_chauthtok`) |
| `crates/mock-idp` | `mock-idp` | Standalone mock SCIM/OIDC server for container testing |
| `crates/e2e` | (tests only) | Integration tests with wiremock mock IdP |

## Standards implemented

This project builds exclusively on open standards — no IdP-specific API
adapters:

- **[SCIM 2.0 — RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643)**
  (Core Schema) — user and group resource types, attribute definitions
- **[SCIM 2.0 — RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644)**
  (Protocol) — REST operations, filtering (`userName eq "..."`,
  `displayName eq "..."`), list responses
- **[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)**
  — `/.well-known/openid-configuration` for endpoint discovery
- **[OAuth 2.0 Device Authorization Grant — RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)**
  — interactive authentication for headless/SSH sessions
- **NSS module interface** (glibc `nss_common.h` / `nss.h`) — `getpwnam_r`,
  `getpwuid_r`, `getgrnam_r`, `getgrgid_r`
- **PAM module interface** (Linux-PAM `security/pam_modules.h`) —
  `pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`

### Supported identity providers

Any provider with a SCIM 2.0 endpoint: Okta, Auth0, Entra ID, Keycloak
(via `scim-for-keycloak` plugin), Google Workspace.

## UID/GID mapping

External UUIDs are deterministically hashed (murmur3, 32-bit, seed 0) into a
configurable numeric range. Every server with the same range config produces
identical UIDs — no coordination database required.

Collision resolution uses linear probing within the range. A local SQLite
cache stores resolved mappings for fast reverse lookups (`getpwuid`).

## Configuration

`/etc/sssd-oidc/config.toml` (override with `SSSD_OIDC_CONFIG` env var):

```toml
[scim]
base_url = "https://example.okta.com/scim/v2"
bearer_token = "your-scim-token"

[oidc]
issuer_url = "https://example.okta.com"
client_id = "your-client-id"
# client_secret = "optional"

[mapping]
uid_range_min = 200000
uid_range_size = 200000
gid_range_min = 200000
gid_range_size = 200000

[user_defaults]
shell = "/bin/bash"
home_template = "/home/{user}"

[cache]
db_path = "/var/lib/sssd-oidc/cache.db"
```

### SSSD integration

```ini
[sssd]
services = nss, pam
domains = oidc

[domain/oidc]
id_provider = proxy
proxy_lib_name = oidc
auth_provider = proxy
proxy_pam_target = oidc
entry_cache_timeout = 3600
cache_credentials = true

[nss]
default_shell = /bin/bash
fallback_homedir = /home/%u
```

## Building

Requires Rust ≥ 1.85.

```sh
cargo build --release
```

Outputs:
- `target/release/libnss_oidc.so` — install as `/usr/lib/libnss_oidc.so.2`
- `target/release/libpam_oidc.so` — install as `/usr/lib/security/pam_oidc.so`

## Testing

### Unit and integration tests

```sh
cargo test --workspace
```

Integration tests in `crates/e2e` use [wiremock](https://crates.io/crates/wiremock)
to run a mock SCIM/OIDC server — no real IdP required.

### Container end-to-end tests

```sh
./test/e2e-container-test.sh
```

Builds the full container image with NSS/PAM modules installed, starts a mock
IdP sidecar, and runs 22 tests covering:

- NSS lookups (by name, UID/GID, enumeration, group membership, initgroups)
- PAM account management (active users permitted, inactive users denied)
- Offline cache fallback (user/group resolution when the IdP is down)
- SSH login (pubkey auth + PAM account check for OIDC-resolved users)
- Deterministic UID mapping and passwd field format validation

Requires Docker (with Compose) or Podman (with podman-compose).

## Implementation status

| Component | Status |
|---|---|
| Config loading (TOML) | ✅ Complete |
| SCIM 2.0 client (user/group lookup) | ✅ Complete |
| UID/GID deterministic mapping | ✅ Complete |
| SQLite cache (store/reverse lookup) | ✅ Complete |
| Service façade (SCIM → model + cache) | ✅ Complete |
| NSS passwd FFI (`getpwnam_r`, `getpwuid_r`) | ✅ Complete |
| NSS group FFI (`getgrnam_r`, `getgrgid_r`) | ✅ Complete |
| NSS enumeration (`setpwent`/`getpwent`/`setgrent`/`getgrent`) | ✅ Complete |
| NSS initgroups (`initgroups_dyn`) | ✅ Complete |
| OIDC discovery | ✅ Complete |
| OIDC device code authentication (RFC 8628) | ✅ Complete |
| PAM authenticate (`pam_sm_authenticate`) | ✅ Complete |
| PAM account management (`pam_sm_acct_mgmt`) | ✅ Complete |
| PAM password change (`pam_sm_chauthtok`) | ✅ Complete (redirects to IdP) |
| Offline cache fallback | ✅ Complete |
| Mock IdP (standalone binary) | ✅ Complete |
| Container build (Containerfile) | ✅ Complete |
| E2E container test suite | ✅ Complete (22 tests incl. SSH login) |

## Research

See [`docs/research/`](docs/research/) for the feasibility study and
architecture decision record.

## Licence

This project is licensed under the [GNU General Public License v2.0 or later](LICENSE)
(SPDX: `GPL-2.0-or-later`).
