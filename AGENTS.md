# AGENTS.md — sssd-oidc

## Project overview

Rust workspace providing NSS and PAM modules that resolve Linux users/groups
and authenticate against OIDC identity providers via SCIM 2.0. Runs behind
SSSD's `proxy` provider (Option D from the research doc).

## Workspace layout

```
sssd-oidc/              # root crate — shared library (config, SCIM client, mapping, cache, service)
├── crates/
│   ├── nss_oidc/       # cdylib — libnss_oidc.so (NSS C ABI)
│   ├── pam_oidc/       # cdylib — pam_oidc.so    (PAM C ABI)
│   └── e2e/            # integration tests (wiremock mock IdP)
└── docs/research/      # architecture decision records
```

## Standards we implement (cite in code and docs)

- SCIM 2.0 Core Schema — [RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643)
- SCIM 2.0 Protocol — [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644)
- OpenID Connect Discovery 1.0 — <https://openid.net/specs/openid-connect-discovery-1_0.html>
- OAuth 2.0 Device Authorization Grant — [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- NSS module interface — glibc `nss_common.h` / `nss.h`
- PAM module interface — Linux-PAM `security/pam_modules.h`

## Key design decisions

1. **Standards only** — no IdP-specific REST adapters. SCIM 2.0 for identity,
   OIDC for auth.
2. **Deterministic UID/GID mapping** — murmur3 hash (seed 0) of external UUID
   into a configurable range. Never use Rust's `DefaultHasher` (not stable
   across compiler versions).
3. **Blocking HTTP** — `reqwest::blocking` because NSS/PAM callbacks are
   synchronous C calls.
4. **SQLite cache** — for UID→external_id reverse lookups; the hash is the
   source of truth, the DB is a cache.
5. **Offline fallback** — on SCIM errors, fall back to the local SQLite cache
   transparently.

## Code conventions

- Rust edition 2024, MSRV 1.85
- `thiserror` for error types, `serde` + `toml` for config, `rusqlite` (bundled) for cache
- NSS/PAM crates produce `cdylib` outputs with `#[unsafe(no_mangle)] extern "C"` FFI
- Unsafe code is confined to `ffi.rs` / `passwd.rs` / `group.rs` in the NSS/PAM crates
- E2E tests use `wiremock` + `tokio::test` with `spawn_blocking` for the sync service layer

## Build & test

```sh
cargo build --workspace
cargo test --workspace
```

## Config

Default path: `/etc/sssd-oidc/config.toml`  
Override: `SSSD_OIDC_CONFIG` env var  
Format: TOML with sections `[scim]`, `[oidc]`, `[mapping]`, `[user_defaults]`, `[cache]`
