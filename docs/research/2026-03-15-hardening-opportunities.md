# Research: Remaining Hardening Opportunities

**Date**: 2026-03-15
**Question**: What additional hardening can we apply beyond the production-readiness gaps?
**Status**: In progress

## Context

The production-readiness gaps identified in
`2026-03-15-production-readiness-gaps.md` have largely been addressed (logging,
PAM subject verification, secret file handling, UID collision probing, cache
TTL, HTTP timeouts, PAM singleton). This document captures a second pass
focusing on input validation, resilience and defence-in-depth.

## Findings

### 1. SCIM URL path injection in `get_user_by_id` / `get_group_by_id`

**File**: `src/scim.rs`, lines 143 and 174

`ScimClient::get_user_by_id` and `get_group_by_id` interpolate the SCIM `id`
directly into the URL path:

```rust
let url = format!("{}/Users/{}", self.base_url, id);
```

A malicious or malformed SCIM `id` containing `../`, `?`, or `#` characters
could alter the request target. While the `id` typically comes from a
prior SCIM response (not user input), defence-in-depth requires encoding it.

**Recommendation**: Percent-encode the `id` segment. The `urlencoding` crate or
manual replacement of reserved characters would suffice.

**Effort**: Small

### 2. No rate-limiting or caching on NSS enumeration

**File**: `src/service.rs`, lines 106–128

`list_all_users()` and `list_all_groups()` issue full SCIM pagination requests
on every call. NSS enumeration (`getent passwd`) can be triggered frequently —
by cron jobs, monitoring agents, or even `ls -la` on a directory with many
owners. Each call paginates the entire user/group set from the IdP.

**Recommendation**: Add a short-lived in-memory cache (e.g., 30–60 s TTL) for
enumeration results, or return cached-only results for enumeration and reserve
live SCIM calls for single-name lookups.

**Effort**: Medium

### 3. `paginate_list` infinite loop risk

**File**: `src/scim.rs`, lines 211–243

If a SCIM server returns a `totalResults` larger than the actual data (or
ignores `startIndex`), the pagination loop runs forever. The only exit
conditions are `all.len() >= resp.total_results` or `fetched == 0`, but a
server that always returns the same non-empty page with a large
`totalResults` would never satisfy either.

**Recommendation**: Add a maximum iteration count (e.g., 1 000 pages or
100 000 total resources) as a safety limit. Log a warning if the limit is
reached.

**Effort**: Small

### 4. JWKS fetched on every PAM authentication

**File**: `src/oidc.rs`, lines 249–288

`OidcClient::validate_id_token` fetches the JWKS from the IdP's `jwks_uri`
on every call. For a server handling multiple SSH logins, this adds latency
and creates unnecessary load on the IdP. JWKS keys rotate infrequently
(typically every 24–48 hours).

**Recommendation**: Cache the fetched `JwkSet` in the `OidcClient` struct
(behind a `Mutex<Option<(Instant, JwkSet)>>`) with a configurable TTL
(default: 1 hour). Refresh on cache miss or expiry, and fall back to a fresh
fetch if the cached key's `kid` doesn't match the token's `kid`.

**Effort**: Medium

### 5. Mutex poison recovery may mask inconsistent state

**Files**: `crates/nss_oidc/src/state.rs`, `crates/pam_oidc/src/state.rs`,
`crates/pam_oidc/src/ffi.rs:98`

Both modules recover from a poisoned `Mutex` with:

```rust
svc_mutex.lock().unwrap_or_else(|e| e.into_inner())
```

This silently continues after a prior panic, but the `Service` (and its
`rusqlite::Connection`) may be in an inconsistent state — for example, a
half-written cache transaction could have been interrupted.

**Recommendation**: Either accept and document this behaviour (NSS/PAM modules
must not crash the host process, so recovery is preferable to `abort`), or
re-initialise the `Service` after a poison by resetting the `OnceLock`. At
minimum, log a warning when recovering from a poisoned lock.

**Effort**: Small (logging) to Medium (re-init)

### 6. SQLite journal mode not set (no WAL)

**File**: `src/cache.rs`, line 48

The cache database uses SQLite's default rollback journal mode. NSS lookups
come from many concurrent processes (each `ls`, `id`, `ssh` invocation loads
the NSS module). The default journal mode uses exclusive locks for writes,
which can cause `SQLITE_BUSY` errors under contention.

**Recommendation**: Set `PRAGMA journal_mode=WAL;` after opening the
connection. WAL mode allows concurrent reads during writes and is the
recommended mode for multi-process access.

**Effort**: Small

### 7. No input length limits on name lookups

**Files**: `src/scim.rs` (filter queries), `src/cache.rs` (SQL parameters),
`src/service.rs` (lookup entry points)

`get_user_by_name` and `get_group_by_name` accept arbitrary-length strings.
While NSS typically constrains input, a direct caller (or a crafted PAM
username) could pass extremely long strings that become expensive SCIM filter
queries or bloat SQL parameters.

**Recommendation**: Reject names exceeding a reasonable limit (e.g., 256
bytes, matching `LOGIN_NAME_MAX` on Linux) early in the `Service` layer.
Return `None` / not-found for oversized inputs.

**Effort**: Small

### 8. Group member list relies on optional `display` field

**File**: `src/service.rs`, line 225

`scim_group_to_model` builds the member list using:

```rust
.filter_map(|m| m.display.clone())
```

The SCIM 2.0 spec (RFC 7643 §8.7.1) marks `display` as optional on
multi-valued complex attributes. If the IdP omits `display` on member
references, the group appears to have zero members — a silent data loss.

**Recommendation**: Fall back to resolving the member's `value` (which is the
member's SCIM `id`) via `get_user_by_id` to obtain the `userName`. Cache
these lookups to avoid N+1 queries on every group resolution.

**Effort**: Medium

## Priority tiers

### Must-fix (security / correctness)

| # | Item | Effort |
|---|------|--------|
| 1 | URL path injection in SCIM by-id lookups | Small |
| 3 | Pagination infinite loop guard | Small |
| 7 | Input length limits on name lookups | Small |

### Should-fix (reliability / performance)

| # | Item | Effort |
|---|------|--------|
| 6 | Enable SQLite WAL mode | Small |
| 4 | Cache JWKS for token validation | Medium |
| 8 | Resolve group members by id when display is absent | Medium |

### Good-to-have (resilience / operational)

| # | Item | Effort |
|---|------|--------|
| 2 | Rate-limit or cache NSS enumeration | Medium |
| 5 | Log warning on mutex poison recovery | Small |

## Open questions

- Should enumeration (`setent`) be disabled entirely and only serve
  cached results? Some NSS modules (e.g., `nss_ldap`) do this.
- Is there a maximum user/group count we should design for? This affects
  the pagination guard limit and enumeration caching strategy.
- Should JWKS cache TTL be configurable, or is a hard-coded one-hour
  default sufficient?
