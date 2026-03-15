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
| `sssd-oidc` (root) | `libsssd_oidc` | Shared library: config, SCIM client, UID mapping, cache, service façade |
| `crates/nss_oidc` | `libnss_oidc.so` | NSS module (`_nss_oidc_getpwnam_r`, `_nss_oidc_getpwuid_r`, `_nss_oidc_getgrnam_r`, `_nss_oidc_getgrgid_r`) |
| `crates/pam_oidc` | `pam_oidc.so` | PAM module (`pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`) |
| `crates/e2e` | (tests only) | End-to-end tests with a mock SCIM/OIDC server (wiremock) |

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

```sh
cargo test --workspace
```

E2E tests use [wiremock](https://crates.io/crates/wiremock) to run a mock
SCIM/OIDC server — no real IdP required.

## Implementation status

| Component | Status |
|---|---|
| Config loading (TOML) | ✅ Complete |
| SCIM 2.0 client (user/group lookup) | ✅ Complete |
| UID/GID deterministic mapping | ✅ Complete |
| SQLite cache (store/reverse lookup) | ✅ Complete |
| Service façade (SCIM → model + cache) | ✅ Complete |
| NSS FFI exports (`getpwnam_r`, etc.) | 🔲 Stubs (wired, not connected to service) |
| PAM FFI exports (`pam_sm_authenticate`) | 🔲 Stubs (device code flow not yet implemented) |
| OIDC device code authentication | 🔲 Not started |
| Access control (SCIM `active` flag) | 🔲 Not started |
| Enumeration (`setpwent`/`getpwent`) | 🔲 Not started |

## Research

See [`docs/research/`](docs/research/) for the feasibility study and
architecture decision record.

## Licence

TBD
