# Research: Production Readiness Gaps

**Date**: 2026-03-15
**Question**: What gaps remain before sssd-oidc can be considered production-ready?
**Status**: Complete

## Context

All functional components (NSS, PAM, SCIM client, OIDC device flow, cache,
mapping, mock-IdP, container E2E tests) are implemented and passing. This
analysis identifies non-functional gaps — operational, security, reliability,
and packaging concerns.

## Findings

### 1. No logging / observability

There is **zero logging** anywhere in the codebase — no `log`, `tracing`,
`syslog`, or even `eprintln!`. NSS/PAM modules running inside `sssd_proxy`
are effectively silent. When something goes wrong in production (SCIM
unreachable, auth failure, cache corruption), operators have no diagnostic
information.

**Recommendation**: Add `syslog`-based logging (e.g., the `syslog` crate or
`log` + `syslog` backend). NSS modules should log at debug/trace level
(they're called very frequently); PAM modules can log at info/warn.

### 2. PAM `pam_sm_authenticate` doesn't verify token subject

`crates/pam_oidc/src/ffi.rs:69` has an explicit TODO:

```rust
// TODO: optionally verify token subject matches username
```

After a successful device-code flow, the module accepts **any** valid token
regardless of which user completed the browser auth. A user could
authenticate as someone else.

**Recommendation**: Decode the `id_token` JWT (at minimum parse the `sub`
claim) and verify it matches the PAM username. This is a **security-critical
gap**.

### 3. SCIM bearer token stored in plaintext config

`config.toml` stores `bearer_token` as a plain string. The config file needs
restrictive permissions (root-only read), but there's no enforcement or
documentation of this. No support for reading secrets from environment
variables, a secrets manager, or a file reference.

**Recommendation**: At minimum, document required file permissions (`chmod
600`). Consider supporting `bearer_token_file = "/run/secrets/scim-token"`
or `bearer_token_env = "SCIM_BEARER_TOKEN"` as alternatives.

### 4. No UID/GID collision handling

The README mentions "collision resolution uses linear probing" but the
actual `mapping.rs` does a bare `hash % range_size` with **no collision
detection or probing**. With 200k range and murmur3, birthday-paradox
collisions become likely around ~500 users (~0.1% at 700 users).

**Recommendation**: Either implement the linear probing described in the
README, or document the collision probability and accept it. For small
deployments (< 200 users) this is very unlikely; for larger ones it's a
real risk.

### 5. No cache TTL enforcement at lookup time

`cache.rs` has `purge_expired()` but nothing ever calls it. The `ttl_seconds`
config field exists but is unused. Stale cache entries (e.g., a user disabled
in the IdP) persist forever until the SCIM lookup overwrites them.

**Recommendation**: Either call `purge_expired()` on Service init or check
`cached_at` in query `WHERE` clauses. Also consider a periodic cleanup.

### 6. No connection timeouts on HTTP client

`ScimClient` and `OidcClient` both use `reqwest::blocking::Client::new()`
with default timeouts. A hung IdP will block NSS calls indefinitely,
freezing `getent passwd`, `ls -la`, or even `ssh`.

**Recommendation**: Set explicit `connect_timeout` (e.g., 5s) and
`timeout` (e.g., 10s) on the `reqwest::blocking::ClientBuilder`.

### 7. PAM module re-initialises on every call

`pam_sm_acct_mgmt` creates a fresh `Config` + `ScimClient` + `Cache` on
every invocation — re-reading `config.toml`, re-opening the SQLite DB. Unlike
the NSS module (which uses `OnceLock` for a singleton), PAM has no caching
of the service instance.

**Recommendation**: Either accept this (PAM calls are infrequent) or use
a similar `OnceLock` singleton as the NSS crate.

### 8. No packaging / installation tooling

There's a `Containerfile` for testing, but no:
- DEB/RPM packaging specs
- `install` target or Makefile
- systemd unit for cache maintenance
- Post-install scripts to configure `nsswitch.conf` / PAM

**Recommendation**: Add at least a `Makefile install` target. For broader
adoption, `nfpm` or `cargo-deb` configs.

### 9. No man pages or admin documentation

README covers architecture well, but there's no:
- `sssd-oidc.conf(5)` man page
- Troubleshooting guide
- IdP-specific setup guides (Okta, Entra ID, Keycloak)

### 10. `group_members` cache doesn't store member UIDs for offline `initgroups`

`Service::lookup_groups_for_user()` returns empty when SCIM is unreachable.
The cache stores group→member-name mappings but not user→group mappings, so
offline `initgroups` (supplementary groups) fails silently.

### 11. Licence is TBD

README says "Licence: TBD". Can't ship without a licence.

### 12. No CI/CD pipeline

No `.github/workflows/`, `.gitlab-ci.yml`, or equivalent. No automated
testing on push/PR.

## Priority tiers

### Must-fix before production (security / correctness)

| # | Item | Effort |
|---|------|--------|
| 2 | Verify `id_token` subject in PAM authenticate | Medium |
| 6 | HTTP client timeouts | Small |
| 11 | Choose and apply a licence | Small |
| 5 | Enforce cache TTL | Small |

### Should-fix (operational reliability)

| # | Item | Effort |
|---|------|--------|
| 1 | Syslog logging | Medium |
| 3 | Secret handling improvements | Small–Medium |
| 4 | UID collision handling (or documented acceptance) | Medium |
| 10 | Offline initgroups support | Medium |

### Nice-to-have (adoption / polish)

| # | Item | Effort |
|---|------|--------|
| 7 | PAM service singleton | Small |
| 8 | DEB/RPM packaging | Medium |
| 9 | Man pages / admin docs | Medium |
| 12 | CI/CD pipeline | Medium |

## Open Questions

- What licence? (GPL-2.0-or-later is conventional for NSS/PAM modules)
- What's the target deployment size? (Collision risk tolerance depends on this)
- Is there a plan for token refresh / SCIM token rotation?
- Should the PAM module support password grant as a fallback for non-interactive logins?
