# Research: SSSD Extension Using OIDC as a Backend

**Date**: 2026-03-13
**Question**: Is it feasible to create an SSSD extension using OIDC as a backend, and what are the best approaches?
**Status**: Complete

## Context

We want to create an SSSD provider that uses OIDC (OpenID Connect) as an identity and authentication backend. This would allow Linux systems to resolve users/groups and authenticate against OIDC providers (Keycloak, Entra ID, Okta, Auth0, etc.) via SSSD's standard NSS/PAM integration.

## Key Finding: SSSD Already Has an IdP Provider (Since ~2024)

**The most important finding is that SSSD already ships an in-tree `idp` provider** (`sssd-idp` package) that does exactly this. It was added in 2024 and supports:

- **Identity lookups** (`id_provider = idp`): Users and groups resolved via IdP REST APIs
- **Authentication** (`auth_provider = idp`): OAuth 2.0 Device Authorization Grant flow (RFC 8628)
- **Supported IdPs**: Microsoft Entra ID (Graph API) and Keycloak (REST Admin API)
- **UID/GID mapping**: Synthetic — UUIDs are hashed into configurable numeric ranges via `sss_idmap`

### Configuration example

```ini
[domain/keycloak]
id_provider = idp
idp_type = keycloak:https://keycloak.example.com/auth/admin/realms/master/
idp_client_id = myclient
idp_client_secret = SECRET
idp_token_endpoint = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/token
idp_device_auth_endpoint = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/auth/device
idp_userinfo_endpoint = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/userinfo
```

## SSSD Provider Plugin Architecture

### How providers are loaded

SSSD's backend process (`sssd_be`) uses a clean `dlopen`-based plugin system:

1. Reads `id_provider`, `auth_provider`, etc. from `sssd.conf`
2. Loads `libsss_<name>.so` from the plugin directory (typically `/usr/lib/sssd/`)
3. Calls `sssm_<name>_init()` — the module constructor
4. For each target (id, auth, access, etc.), calls `sssm_<name>_<target>_init()`
5. Target constructors register async tevent handlers via `dp_set_method()`

### Provider targets and methods

| Target | Config Option | Key Method |
|--------|--------------|------------|
| `DPT_ID` | `id_provider` | `DPM_ACCOUNT_HANDLER` — user/group/initgroup lookups |
| `DPT_AUTH` | `auth_provider` | `DPM_AUTH_HANDLER` — PAM authentication |
| `DPT_ACCESS` | `access_provider` | `DPM_ACCESS_HANDLER` — authorization checks |
| `DPT_CHPASS` | `chpass_provider` | `DPM_AUTH_HANDLER` — password changes |
| `DPT_SUDO` | `sudo_provider` | `DPM_SUDO_HANDLER` — sudo rules |
| `DPT_SUBDOMAINS` | `subdomains_provider` | `DPM_DOMAINS_HANDLER` — subdomain discovery |
| `DPT_SESSION` | `session_provider` | `DPM_SESSION_HANDLER` — session management |

### Minimum symbols for a new provider

```c
errno_t sssm_<name>_init(TALLOC_CTX *, struct be_ctx *, struct data_provider *, const char *, void **);
errno_t sssm_<name>_id_init(TALLOC_CTX *, struct be_ctx *, void *, struct dp_method *);
errno_t sssm_<name>_auth_init(TALLOC_CTX *, struct be_ctx *, void *, struct dp_method *);
```

All handlers follow the tevent async pattern (`_send()`/`_recv()` pairs) and must write results to the sysdb cache using `sysdb_store_user()`, `sysdb_store_group()`, etc.

### Existing `idp` provider architecture

The `idp` provider uses a **subprocess model**: `sssd_be` never does HTTP calls itself. Instead it spawns `oidc_child` (a separate binary) via pipe IPC:

```
sssd_be (idp_id.c / idp_auth.c)
  └─ fork/exec oidc_child
       ├─ stdin: client_secret (+ device code JSON for auth)
       └─ stdout: JSON array (identity) or UUID string (auth)
```

`oidc_child` uses libcurl for HTTP and jansson for JSON. It handles:
- **Client credentials grant** for identity lookups (user/group enumeration)
- **Device authorization grant** (RFC 8628) for interactive authentication
- IdP-specific REST APIs (Graph API for Entra ID, Admin REST API for Keycloak)

## Options Considered

### Option A: Use the existing `idp` provider as-is

| Pros | Cons |
|------|------|
| Zero development effort | Only supports Keycloak and Entra ID |
| Maintained by SSSD upstream (Red Hat) | Only name-based lookups (no UID/GID lookup) |
| Ships as `sssd-idp` package | Auth requires device code flow (needs browser) |
| Proven integration with sysdb cache | No offline support (online check is a no-op) |
| | No enumeration (can't list all users) |
| | No support for Okta, Auth0, or generic OIDC |

**Effort**: None (config only)

### Option B: Contribute a new IdP type to the existing `idp` provider

Add support for a new IdP (e.g., Okta, generic SCIM) by extending `oidc_child_id.c`.

| Pros | Cons |
|------|------|
| Leverages all existing infrastructure | Must write C code, contribute upstream |
| Natural home for the feature | Tied to SSSD release cadence |
| Benefits from sysdb, idmap, caching | Still limited to device code auth flow |
| Community support | Each new IdP needs its own REST API adapter |

**Effort**: Medium (C, upstream contribution process)

### Option C: Write a new out-of-tree SSSD provider in C

Create `libsss_myoidc.so` that implements the provider interface.

| Pros | Cons |
|------|------|
| Full control over features | **No stable public API** — headers are internal |
| Can implement custom auth flows | Deep dependency on SSSD internals (talloc, tevent, sysdb, ldb) |
| Can support any OIDC provider | Must track SSSD internal API changes across versions |
| Can add UID lookup, enumeration, etc. | Significant C development effort |
| | No ABI versioning — silent breakage risk |

**Effort**: High (C, reverse-engineering internal APIs)

### Option D: Use the `proxy` provider with custom NSS/PAM modules (Rust)

Use SSSD's `proxy` provider to delegate to a custom NSS module (for identity) and a custom PAM module (for auth), both written in Rust.

```ini
[domain/oidc]
id_provider = proxy
proxy_lib_name = oidc        # loads libnss_oidc.so.2
auth_provider = proxy
proxy_pam_target = oidc       # uses /etc/pam.d/oidc → pam_oidc.so
```

| Pros | Cons |
|------|------|
| **Stable, public interfaces** (NSS/PAM are POSIX) | Loses SSSD's sysdb caching granularity |
| **Out-of-tree, no SSSD internal deps** | Proxy provider is single-threaded (serializes requests) |
| Can write in Rust (safety, ecosystem) | Must implement NSS module C ABI (`_nss_oidc_getpwnam_r`, etc.) |
| Works with any SSSD version | Two separate components to maintain (NSS + PAM) |
| Prior art: `pam-oauth2` exists in Rust | PAM device-code flow UX is awkward |
| Can support any OIDC provider | No UID/GID lookup unless you maintain a local mapping DB |

**Effort**: Medium (Rust with C FFI for NSS/PAM interfaces)

### Option E: Write a standalone daemon that replaces SSSD

Build a custom NSS/PAM provider daemon in Rust that talks OIDC directly, without SSSD.

| Pros | Cons |
|------|------|
| Full control, no SSSD dependency | Must reimplement caching, offline support, failover |
| Clean Rust architecture | Loses SSSD's mature infrastructure |
| Can optimize for OIDC-only use case | Must handle nscd interaction, memcache, etc. |
| | Significant engineering effort |

**Effort**: Very High

## Recommendation

The answer depends on what you're trying to achieve:

### If you need Keycloak or Entra ID support today
→ **Option A**: Just use `id_provider = idp`. It already works.

### If you need to support additional OIDC providers (Okta, Auth0, generic)
→ **Option B** (upstream contribution) or **Option D** (proxy + Rust NSS/PAM)

**Option D is the recommended path for a Rust project** because:
1. NSS and PAM are stable, well-documented C interfaces
2. Rust has good C FFI support and existing PAM crate (`pam`)
3. The `proxy` provider handles SSSD integration (caching, responders)
4. You're decoupled from SSSD internals — works across versions
5. Prior art exists: `datajoint-company/pam-oauth2` is a Rust PAM module for OIDC

### If you want maximum control and deep integration
→ **Option C** (out-of-tree C provider), but be prepared for maintenance burden

## Architecture for Option D (Recommended Rust Approach)

```
┌─────────────────────────────────────────────────┐
│                    SSSD                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ sssd_nss │  │ sssd_pam │  │   sssd_be     │  │
│  │          │  │          │  │  (proxy mode)  │  │
│  └────┬─────┘  └────┬─────┘  └──┬─────┬──────┘  │
│       │              │           │     │         │
│  ┌────▼─────┐  ┌─────▼────┐     │     │         │
│  │nss_sss.so│  │pam_sss.so│     │     │         │
│  └──────────┘  └──────────┘     │     │         │
└─────────────────────────────────┼─────┼─────────┘
                                  │     │
                    ┌─────────────▼┐  ┌─▼──────────────┐
                    │libnss_oidc.so│  │ pam_oidc.so    │
                    │  (Rust/FFI)  │  │ (Rust/FFI)     │
                    │              │  │                 │
                    │ NSS methods: │  │ PAM methods:    │
                    │ getpwnam_r   │  │ pam_sm_auth     │
                    │ getpwuid_r   │  │ pam_sm_setcred  │
                    │ getgrnam_r   │  │ pam_sm_acct_mgmt│
                    │ getgrgid_r   │  │                 │
                    │ setpwent     │  │ Auth flows:     │
                    │ getpwent_r   │  │ - Device code   │
                    │ endpwent     │  │ - ROPC (if avail│
                    └──────┬───────┘  │ - Token/cert    │
                           │          └────────┬────────┘
                           │                   │
                    ┌──────▼───────────────────▼────────┐
                    │     Shared Rust OIDC Library       │
                    │                                    │
                    │  - OIDC discovery (.well-known)    │
                    │  - Client credentials grant        │
                    │  - Device authorization grant      │
                    │  - Token validation (JWT/JWKS)     │
                    │  - User/group REST API adapters    │
                    │  - Local UID/GID mapping (SQLite)  │
                    │  - Caching layer                   │
                    └────────────────────────────────────┘
```

### Key components to implement

1. **`libnss_oidc.so`** — NSS module exposing `_nss_oidc_getpwnam_r`, `_nss_oidc_getpwuid_r`, `_nss_oidc_getgrnam_r`, etc.
2. **`pam_oidc.so`** — PAM module implementing `pam_sm_authenticate` with device code or token-based auth
3. **Shared OIDC client library** — Handles all OAuth2/OIDC protocol flows, JWT validation, and IdP-specific REST APIs
4. **UID/GID mapping store** — SQLite-based persistent mapping from OIDC subject/UUID to local UID/GID (similar to SSSD's idmap but portable)

### Rust crates to leverage

- `openidconnect` — Full OIDC client implementation (discovery, device code, token validation)
- `scim_v2` (or hand-rolled) — SCIM 2.0 client for standard identity lookups
- `jsonwebtoken` — JWT creation/validation
- `reqwest` — HTTP client
- `rusqlite` — SQLite for UID mapping cache
- `pam` or `pam-sys` — PAM module FFI bindings
- `libc` — NSS module C ABI types
- `nix` — Unix system call wrappers

## Decision: Option D (Proxy + Rust) for Okta + Caching + Group Mapping

**Requirements**: Okta as IdP, caching for network outages, group mapping.

**Decision**: Option D is the best fit because:

1. **Okta support**: Only Options C/D/E can support Okta. Options A/B are limited to
   Keycloak and Entra ID. Okta exposes REST APIs for user/group management:
   - `GET /api/v1/users?search=profile.login eq "..."` — user lookup
   - `GET /api/v1/groups?q=...` — group lookup
   - `GET /api/v1/users/{id}/groups` — user→group membership
   - `POST /oauth2/v1/device/authorize` — device code auth (RFC 8628)

2. **Caching**: SSSD's proxy provider automatically caches all NSS responses in
   its sysdb (LDB) cache. The Rust NSS module is only the "online source" —
   SSSD handles cache storage, expiration (`entry_cache_timeout`), and serving
   cached data when the backend is unreachable. **No caching reimplementation
   needed.**

3. **Group mapping**: The NSS module implements `_nss_oidc_initgroups_dyn()`,
   which SSSD calls for group membership. Okta group UUIDs are mapped to stable
   local GIDs via a persistent SQLite store. SSSD caches the results in sysdb.

4. **Stable API**: NSS and PAM are POSIX-standard C interfaces — no dependency
   on SSSD internals, works across SSSD versions.

5. **Rust ecosystem**: `openidconnect`, `reqwest`, `rusqlite`, `pam` crates
   provide the building blocks.

### Standards-Based Approach (Multi-IdP)

Rather than using Okta-specific APIs (e.g., `/api/v1/users`), we should use
**standard protocols** so the same code works across Okta, Auth0, Keycloak,
Entra ID, and any other compliant provider. Two complementary standards cover
our needs:

#### 1. SCIM 2.0 for Identity Lookups (RFC 7643/7644)

**SCIM (System for Cross-domain Identity Management)** is the IETF standard
REST API for user and group management. It provides exactly the endpoints we
need for NSS identity lookups:

| NSS function | SCIM API call |
|---|---|
| `getpwnam(name)` | `GET /scim/v2/Users?filter=userName eq "{name}"` |
| `getpwuid(uid)` | Local hash→UUID cache → `GET /scim/v2/Users/{id}` |
| `getgrnam(name)` | `GET /scim/v2/Groups?filter=displayName eq "{name}"` |
| `getgrgid(gid)` | Local hash→UUID cache → `GET /scim/v2/Groups/{id}` |
| `initgroups(user)` | `GET /scim/v2/Users/{id}` → extract `groups` attribute, or `GET /scim/v2/Groups?filter=members eq "{user_id}"` |

**SCIM provider support:**

| Provider | SCIM 2.0 Support | Notes |
|----------|-----------------|-------|
| Okta | ✅ Full | `/scim/v2/Users`, `/scim/v2/Groups` |
| Auth0 | ✅ Inbound SCIM | Supports SCIM provisioning endpoints |
| Entra ID | ✅ Full | Via Microsoft Graph SCIM endpoint |
| Keycloak | ✅ Via plugin | `scim-for-keycloak` plugin |
| Google Workspace | ✅ Full | Cloud Identity SCIM API |

SCIM provides a **standard schema** (RFC 7643) with `userName`, `displayName`,
`emails`, `groups`, and `id` fields — no IdP-specific field mapping needed.

#### 2. OIDC Token Claims for Authentication + Group Membership

For authentication, we use standard OIDC (device code flow). For group
membership, we can **include groups as a claim in the OIDC token** rather
than making separate API calls:

- **Okta**: Add a `groups` claim to the authorization server → token contains
  `"groups": ["Everyone", "Engineering"]`
- **Auth0**: Configure `groups` scope or use Rules/Actions to add groups to tokens
- **Keycloak**: Built-in `groups` mapper adds groups to tokens automatically
- **Entra ID**: Set `groupMembershipClaims` in app manifest → token contains
  group object IDs

This means the PAM module can extract group memberships directly from the
authenticated user's token, reducing API calls and working with standard OIDC.

#### 3. SCIM is Required — No IdP-Specific Fallbacks

We require the IdP to expose a SCIM 2.0 endpoint. There are no IdP-specific
adapters (no Okta `/api/v1/`, no Keycloak Admin REST API). This keeps the
codebase simple and ensures we only depend on standards.

If an IdP doesn't natively support SCIM, the administrator must enable it
(e.g., install the `scim-for-keycloak` plugin for Keycloak) before using
this tool.

#### Authentication (PAM Module)

All providers support standard OIDC. The PAM module uses only standard
endpoints discovered via `/.well-known/openid-configuration`:

1. **`pam_sm_authenticate` (preauth)**: POST to the `device_authorization_endpoint`,
   display verification URI + user code to the user
2. **`pam_sm_authenticate` (poll)**: Poll the `token_endpoint` until user completes
   browser auth, validate the returned token's `sub` claim matches the login user
3. **Group extraction**: Read `groups` claim from id_token/access_token (if configured
   in the IdP) — no additional API calls needed

#### UID/GID Mapping — Deterministic Hash-Based

**UID/GID consistency across servers is critical.** When a user logs into multiple
servers, they must get the same UID everywhere. Inconsistent UIDs cause:

- **NFS/shared filesystem breakage**: Files owned by UID 200042 on server A appear
  owned by a different user (or nobody) on server B
- **SSH failures**: `~/.ssh/authorized_keys` ownership checks fail
- **Audit log confusion**: Numeric UIDs in logs can't be correlated across servers
- **Backup/restore corruption**: File permissions silently change

##### Approach: Deterministic hashing (no coordination required)

We use the same approach as SSSD's `sss_idmap`: hash the Okta UUID string into
a UID/GID within a configurable range. Since the hash function is deterministic,
every server independently produces the same UID for the same Okta user — no
shared database, no network dependency, no coordination.

```rust
/// Map an Okta UUID to a local UID within [range_min, range_min + range_size)
///
/// Uses murmur3 (32-bit) for guaranteed cross-version, cross-platform stability.
/// Rust's DefaultHasher is NOT stable across compiler versions and must not be used.
fn okta_uuid_to_uid(uuid: &str, range_min: u32, range_size: u32) -> u32 {
    let hash = murmur3::murmur3_32(&mut uuid.as_bytes(), /* seed */ 0)
        .expect("murmur3 hashing failed");
    range_min + (hash % range_size)
}
```

**Important**: We use murmur3 (via the `murmur3` crate) rather than Rust's
`DefaultHasher` because `DefaultHasher` is explicitly **not guaranteed stable**
across Rust compiler versions. A hash function change between builds would
silently reassign UIDs and break file ownership across all servers. Murmur3's
algorithm is fully specified and produces identical output on every platform
and every build.

**Collision handling**: With a 200,000-slot range and typical org sizes (<10,000
users), collision probability is low (~25% chance of any collision at 10k users
via birthday problem). If a collision occurs, we use linear probing within the
range. A local SQLite cache stores the resolved mapping so collisions are only
resolved once per server.

##### Configuration

```ini
# /etc/sssd-oidc/config.toml (or similar)
[mapping]
uid_range_min = 200000
uid_range_size = 200000    # UIDs: 200000–399999
gid_range_min = 200000
gid_range_size = 200000    # GIDs: 200000–399999
```

All servers must use the **same range configuration** to produce consistent mappings.

##### Local cache (SQLite)

A local SQLite database caches resolved mappings for fast `getpwuid()` reverse
lookups (UID → Okta UUID → user attributes). This is a **cache**, not the source
of truth — the hash function is the source of truth.

```sql
CREATE TABLE uid_cache (
    okta_id TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    uid INTEGER UNIQUE NOT NULL,
    cached_at INTEGER NOT NULL    -- epoch seconds
);

CREATE TABLE gid_cache (
    okta_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    gid INTEGER UNIQUE NOT NULL,
    cached_at INTEGER NOT NULL
);
```

##### Alternative: Okta custom profile attributes

For organizations that prefer explicit control, Okta supports custom user profile
attributes. A `posixUid` and `posixGid` attribute can be added to the Okta user
profile schema and populated by an admin or provisioning workflow. The NSS module
would read these directly instead of hashing. This is more work to set up but
gives full administrative control over UID assignments.

### SSSD Configuration

```ini
[sssd]
services = nss, pam
domains = okta

[domain/okta]
id_provider = proxy
proxy_lib_name = oidc
auth_provider = proxy
proxy_pam_target = oidc
entry_cache_timeout = 3600
# Serve cached data when Okta is unreachable:
cache_credentials = true

[nss]
default_shell = /bin/bash
fallback_homedir = /home/%u
```

## Feature Parity Gap Analysis vs LDAP Backend

The SSSD LDAP provider (`id_provider=ldap`) is the most fully featured backend.
The table below shows every feature it supports and our coverage status.

### Already Covered

| Feature | LDAP Mechanism | Our Approach | Status |
|---------|---------------|--------------|--------|
| **User lookup** (name, UID) | LDAP search | SCIM `GET /Users?filter=...` | ✅ Designed |
| **Group lookup** (name, GID) | LDAP search | SCIM `GET /Groups?filter=...` | ✅ Designed |
| **initgroups** (user→groups) | LDAP `memberOf`/nested | SCIM group membership + token `groups` claim | ✅ Designed |
| **Authentication** | LDAP bind | OIDC Device Code flow (RFC 8628) | ✅ Designed |
| **UID/GID mapping** | SID→UID hash (`sss_idmap`) | UUID→UID hash (murmur3) | ✅ Designed |
| **Caching / offline** | sysdb (LDB) | SSSD proxy provider auto-caches | ✅ Built-in |
| **Online/offline detection** | `DPM_CHECK_ONLINE` LDAP bind | HTTP health check to SCIM endpoint | ✅ Trivial |

### Gaps to Address

| Feature | LDAP Mechanism | SCIM/OIDC Equivalent | Priority | Effort |
|---------|---------------|---------------------|----------|--------|
| **Password change** | LDAP Modify ExtOp (RFC 3062) or `userPassword` modify | No standard SCIM password change. Could use SCIM `PATCH /Users/{id}` with `password` attribute, but IdP support varies. Likely better to redirect to IdP web portal. | High | Low |
| **Access control** | `ldap_access_filter`, account expiry (`shadow`, `ad`, `nds`), `authorizedService`, host-based, ppolicy lockout | SCIM user `active` attribute for basic enable/disable. Group-based access rules (user must be in an allowed group). Account expiry from SCIM `meta.lastModified` or custom attributes. | High | Medium |
| **Enumeration** | Periodic bulk LDAP search of all users/groups | SCIM `GET /Users` and `GET /Groups` (paginated via `startIndex` + `count`). Beware IdP rate limits. | Medium | Medium |
| **Sudo rules** | `sudoRole` LDAP objects | No SCIM equivalent. Options: (a) store sudo rules in a local file/DB managed externally, (b) use a custom SCIM extension schema, (c) skip — use host-local `/etc/sudoers.d/` managed by config management. | Medium | N/A (skip) |
| **SSH host keys** | `sshPublicKey` LDAP attribute | No SCIM equivalent. Options: (a) SCIM extension attribute, (b) skip — use `ssh-keygen` + config management. Not typically managed via IdP. | Low | N/A (skip) |
| **AutoFS maps** | `automountMap`/`automountEntry` LDAP objects | No SCIM equivalent. Not relevant to OIDC/cloud IdPs. Skip. | Low | N/A (skip) |
| **IP host/network resolver** | `ipHost`/`ipNetwork` LDAP objects | No SCIM equivalent. Skip — use DNS. | Low | N/A (skip) |
| **Netgroups** | NIS netgroup LDAP objects | Legacy NIS concept. Skip. | Low | N/A (skip) |
| **Services** (`/etc/services`) | `ipService` LDAP objects | No SCIM equivalent. Skip — use local files. | Low | N/A (skip) |
| **Dynamic DNS update** | `nsupdate` after LDAP connect | Not relevant — no LDAP connection. Skip. | Low | N/A (skip) |
| **Certificate mapping** | X.509 cert → user via `certmap` rules | Could map `x509Certificates` SCIM attribute to users. Low demand for OIDC use cases. | Low | Medium |
| **SubID ranges** | `subordinateUid`/`subordinateGid` ranges | No SCIM equivalent. Very niche (container user namespaces). Skip. | Low | N/A (skip) |
| **Failover** | Multiple `ldap_uri` + DNS SRV | Configure multiple SCIM base URLs. OIDC discovery handles auth endpoint failover. | Medium | Low |
| **Schema flexibility** | RFC 2307 / 2307bis / IPA / AD attribute maps | SCIM has a fixed standard schema (RFC 7643). No mapping needed. | N/A | N/A |

### Summary

For a practical MVP with feature parity on the features that **matter for OIDC/cloud IdP use cases**:

**Must have (MVP):**
- ✅ User/group identity lookups (SCIM)
- ✅ Authentication (OIDC device code)
- ✅ Group membership (SCIM + token claims)
- ✅ UID/GID mapping (deterministic hash)
- ✅ Caching/offline (SSSD proxy)
- 🔲 Access control (SCIM `active` flag + group-based rules)
- 🔲 Password change (redirect to IdP portal, or SCIM PATCH if supported)

**Nice to have:**
- 🔲 Enumeration (SCIM paginated listing)
- 🔲 Failover (multiple SCIM endpoints)
- 🔲 Online check (HTTP health check)

**Out of scope (no SCIM equivalent, not relevant to cloud IdPs):**
- Sudo rules, AutoFS, SSH host keys, IP hosts/networks, netgroups, services, dynamic DNS, SubID ranges, certificate mapping

These are better handled by config management tools (Ansible, Puppet) or local files.

## Open Questions

- **Authentication UX**: Device code flow requires a browser on a separate device. Is this acceptable for the target use case? (Note: ROPC is deprecated in OAuth 2.1)
- ~~**UID/GID stability across machines**~~: **Resolved** — use deterministic hash-based mapping. All servers with the same range config produce identical UIDs for the same Okta UUID. No coordination needed.
- **Okta API rate limits**: Okta enforces rate limits on API calls. The NSS module must handle 429 responses gracefully. SSSD's caching helps reduce call frequency.
- ~~**Hash function choice**~~: **Resolved** — use murmur3 (fully specified, cross-platform stable). `DefaultHasher` is explicitly rejected.
- **Scope**: Do we need sudo rules, autofs, SELinux context, or SSH key support? Or just basic identity + auth?

## References

- [SSSD IdP Introduction (sssd.io)](https://sssd.io/docs/idp/idp-introduction.html)
- [SSSD Architecture (sssd.io)](https://sssd.io/docs/architecture.html)
- [SSSD source: src/providers/idp/](https://github.com/SSSD/sssd/tree/main/src/providers/idp)
- [SSSD source: src/oidc_child/](https://github.com/SSSD/sssd/tree/main/src/oidc_child)
- [SSSD source: src/providers/data_provider/dp_modules.c](https://github.com/SSSD/sssd/blob/main/src/providers/data_provider/dp_modules.c)
- [SSSD Internals documentation](https://docs.pagure.org/sssd.sssd/developers/internals.html)
- [SSSD GitHub issue #7229 — OIDC support](https://github.com/SSSD/sssd/issues/7229)
- [FOSDEM 2025 — SSSD and IdPs](https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4756-sssd-and-idps/)
- [pam-oauth2 (Rust PAM OIDC module)](https://github.com/datajoint-company/pam-oauth2)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
