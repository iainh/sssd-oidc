# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-03-19

### Added

- Configurable offline auth policy (`security.offline_auth_policy`): choose
  `cached_status` (default) or `deny` for fail-closed behaviour when SCIM is
  unreachable ([ae4dd2b])

### Changed

- Validate OIDC discovery issuer matches configured `issuer_url` and enforce
  HTTPS on all discovered endpoints (OIDC Discovery §4.3). Add `allow_insecure`
  config option for local development ([add9e5e])
- Reduce mutex hold time in NSS lookups — SCIM HTTP requests no longer block
  other NSS lookups in the same process ([9ec40e5])
- Clamp device-flow polling interval to minimum 5 s and persistently increase
  on `slow_down` responses per RFC 8628 §3.5 ([e3822d8])
- Move unverified JWT decoder to test-only scope to prevent misuse ([100053f])

### Fixed

- Correct `initgroups_dyn` duplicate GID detection — scan the live write cursor
  instead of the initial snapshot ([4d74c34])
- Bump RPM spec version to 0.2.0 ([c0f930f])

### Performance

- Add SQLite indexes on `uid_cache.login`, `gid_cache.name`, and
  `group_members.member_name` to avoid full table scans ([1d1dcb8])

## [0.2.0] — 2026-03-16

### Changed

- **Replace reqwest with ureq** for all HTTP requests. ureq is blocking by
  default, a natural fit for the synchronous NSS/PAM C ABI callbacks, and pulls
  in far fewer transitive dependencies ([52506f1])
- Replace ASCII architecture diagram in README with Mermaid chart ([af467bb])

## [0.1.0] — 2026-03-16

Initial release — SSSD proxy-backed NSS and PAM modules resolving Linux
users/groups against OIDC identity providers via SCIM 2.0.

### Added

- **NSS module** (`libnss_oidc.so`):
  - `getpwnam_r` / `getpwuid_r` for user lookups via SCIM ([2edcfe1])
  - `getgrnam_r` / `getgrgid_r` for group lookups via SCIM ([7f33e8e])
  - `setpwent` / `getpwent_r` / `endpwent` and `setgrent` / `getgrent_r` /
    `endgrent` for SSSD enumerate mode with SCIM pagination ([b8c75f6])
  - `initgroups_dyn` for supplementary group lookup ([8abd53c])
- **PAM module** (`pam_oidc.so`):
  - `pam_sm_authenticate` wired to OIDC device authorization grant
    (RFC 8628) ([0289b37], [0d30f7c])
  - `pam_sm_acct_mgmt` checking SCIM user `active` flag with cache
    fallback ([db52d3b])
  - `pam_sm_chauthtok` redirecting users to their IdP portal ([522d633])
  - JWT signature validation and token subject verification ([6c3b08a])
- **OIDC client**: discovery document parsing and device authorization
  grant flow ([a18170a], [0d30f7c])
- **SCIM client**: user/group lookups, health check for online/offline
  detection, filter value escaping ([b40bdd0], [0f99a5c])
- **SQLite cache**: user/group caching with configurable TTL, group member
  persistence, offline fallback, ownership and permission hardening
  ([21bc96e], [0a67318], [52aca39])
- **Deterministic UID/GID mapping**: murmur3 hash with linear probing for
  collision handling ([07773d4])
- **Configuration**:
  - TOML config with `[scim]`, `[oidc]`, `[mapping]`, `[user_defaults]`,
    `[cache]` sections
  - SCIM bearer token moved to separate file with permission
    checks ([a0e293f])
  - Annotated example configuration file ([02f919d])
- **Syslog-based tracing** via `tracing-subscriber` with per-facility log
  routing (LOG_DAEMON for NSS, LOG_AUTHPRIV for PAM) ([152ba05])
- **Container-based E2E tests** with multi-arch support, SSH login tests,
  and mock IdP ([a05ba08], [de29ecc], [a39865e], [9e55e2c])
- **CI**: GitHub Actions workflow for fmt, clippy, tests, E2E, and RPM
  builds for RHEL 9 ([88d9c30], [9008d79])
- **Nix flake** dev shell with Rust toolchain, podman, and PAM
  headers ([8275a43])
- GPL-2.0-or-later licence ([9a82f33])

### Fixed

- Enforce cache TTL at lookup time ([3b511d0])
- Add connection and request timeouts to HTTP clients ([dd3dca1])
- Offline `initgroups` fallback via `group_members` reverse lookup ([c69d38e])
- Root-ownership check using euid instead of `cfg!(test)` ([ae1ad49])

### Breaking Changes

- `bearer_token` field removed from `[scim]` config section; token must now be
  placed in `/etc/sssd-oidc/scim-token` (or a custom path via
  `bearer_token_file`) ([a0e293f])

[Unreleased]: https://github.com/iainh/sssd-oidc/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/iainh/sssd-oidc/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/iainh/sssd-oidc/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iainh/sssd-oidc/releases/tag/v0.1.0
