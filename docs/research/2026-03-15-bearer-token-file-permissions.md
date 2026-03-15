# Research: Bearer Token File Separation & Permission Checks

**Date**: 2026-03-15
**Question**: Should we move the SCIM bearer token to its own file, and can we refuse to start if file permissions are insecure?
**Status**: Complete

## Context

Currently `config.toml` stores `bearer_token` as a plaintext string in the
`[scim]` section. This means the entire config file must be locked down to
protect one secret, and config management tools (Ansible, etc.) must treat the
whole file as sensitive. Moving the token to a dedicated file allows the config
itself to be more freely readable (e.g. `0644`) while the secrets file is
`0600` root-only.

## Prior Art: Permission Checks in Well-Known Software

| Software | What it checks | Behaviour |
|---|---|---|
| **OpenSSH** (`ssh`) | Private key files must be `0600` (or `0400`). Checks owner and group/other bits. Also checks every parent directory in the path. | **Hard fail** — refuses to use the key: `"Permissions 0644 for '~/.ssh/id_rsa' are too open. This private key will be ignored."` |
| **WireGuard** (`wg-quick`) | Checks if `/etc/wireguard/*.conf` is world-accessible. | **Warning only** — prints `"Warning: /etc/wireguard/wg0.conf is world accessible"` but continues. |
| **OpenVPN** | Relies on OS-level file permissions; documents that `--secret` key files should be `0600`. | No runtime check — documentation only. |
| **Prometheus** | Supports `bearer_token_file` to read tokens from a separate file. | No permission check on the file — relies on container/K8s `defaultMode: 0400` conventions. |
| **SSSD** (native) | Config file `/etc/sssd/sssd.conf` must be owned by root and mode `0600`. | **Hard fail** — refuses to start if permissions are wrong. |
| **Kubernetes Secrets** | Mounted as files with `defaultMode: 0644` (or user-specified, commonly `0400`). | Enforced by kubelet at mount time, not by the consuming application. |

### Conclusion from Prior Art

The SSH and SSSD patterns are the strongest precedents for our use case. Both
are security-critical system components that **hard-fail** on bad permissions.
Since sssd-oidc plugs into the same trust boundary (NSS/PAM running as root),
following SSSD's own convention is the most defensible choice.

## Proposed Design

### Config Changes

Add `bearer_token_file` as an alternative to `bearer_token` in `[scim]`:

```toml
[scim]
base_url = "https://example.okta.com/scim/v2"
# Option A: inline (existing, still supported)
bearer_token = "secret-token-here"

# Option B: file reference (new, preferred)
bearer_token_file = "/etc/sssd-oidc/scim-token"
```

Exactly one of `bearer_token` or `bearer_token_file` must be set (error if
both or neither).

### Permission Checks

Check **both** the config file and the token file at load time.

#### What to check

| Check | Rationale |
|---|---|
| **Owner is root (uid 0)** | NSS/PAM modules run as root; no other user should own these files. |
| **Group-other read/write bits are clear** (mode `& 0o077 == 0`) | Equivalent to requiring `0600` or `0400`. Matches OpenSSH's check. |
| **File is a regular file** (not symlink, FIFO, etc.) | Prevents TOCTOU attacks via symlink substitution. Note: `lstat` not `stat` to avoid following symlinks. |
| **Parent directory owner is root** | Optional hardening — OpenSSH does this. May be overkill for `/etc/sssd-oidc/`. |

#### Implementation (Rust)

```rust
use std::os::unix::fs::MetadataExt;
use std::fs;
use std::path::Path;

fn check_secret_file_permissions(path: &Path) -> Result<(), ConfigError> {
    // Use symlink_metadata (lstat) to avoid following symlinks
    let meta = fs::symlink_metadata(path)
        .map_err(|e| ConfigError::Read { path: path.to_owned(), source: e })?;

    if !meta.is_file() {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: "not a regular file".into(),
        });
    }

    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: format!(
                "permissions {:04o} are too open; must not be accessible by group or others (expected 0600 or 0400)",
                mode & 0o777
            ),
        });
    }

    #[cfg(target_os = "linux")]
    if meta.uid() != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            detail: format!("owned by uid {} but must be owned by root (uid 0)", meta.uid()),
        });
    }

    Ok(())
}
```

#### Behaviour on failure

**Hard fail** — return an error from `Config::load()`. For NSS this means
the lookup returns `NSS_STATUS_UNAVAIL`; for PAM it means
`PAM_AUTHINFO_UNAVAIL`. Both cause SSSD's proxy provider to fall through
to the next module, which is the correct degradation path.

The error message should be actionable, following OpenSSH's style:

```
error: permissions 0644 for '/etc/sssd-oidc/scim-token' are too open;
       must not be accessible by group or others.
       Run: chmod 600 /etc/sssd-oidc/scim-token
```

### Which files to check

| File | Check permissions? | Rationale |
|---|---|---|
| `config.toml` (when it contains `bearer_token`) | **Yes** — must be `0600` root-only | Contains the secret inline |
| `config.toml` (when using `bearer_token_file`) | **No** — can be `0644` | No secrets in the config itself |
| Token file (`bearer_token_file`) | **Yes** — must be `0600` root-only | Contains the secret |

This is the key usability win: separating the token means `config.toml` can
be checked into version control, inspected by non-root admins, etc.

## Options Considered

| Option | Pros | Cons | Effort |
|---|---|---|---|
| **A: `bearer_token_file` + hard-fail permission check** | Follows SSH/SSSD precedent; clear error; separates secrets from config | Slightly more complex config loading | Small |
| **B: Warn only (WireGuard style)** | Less disruptive | Users may ignore warnings; NSS/PAM have no good warning channel (syslog only) | Small |
| **C: Environment variable (`SCIM_BEARER_TOKEN`)** | Good for containers/systemd `EnvironmentFile` | Env vars visible in `/proc/PID/environ` to same-uid processes; doesn't help with config file perms | Small |
| **D: All three (`bearer_token`, `bearer_token_file`, env var)** | Maximum flexibility | More code paths to test; env var has the /proc leak issue | Medium |

## Recommendation

**Option A** — `bearer_token_file` with hard-fail permission checks — as the
primary new feature. Keep the existing inline `bearer_token` for backwards
compatibility but add permission checks on `config.toml` when it contains
inline secrets.

Skip the env var option for now. Environment variables are visible to any
process running as the same uid via `/proc/<pid>/environ`, which is arguably
worse than a `0600` file. If container users need it, they can bind-mount a
secrets file (which is what Kubernetes does natively with Secret volumes).

### Suggested file layout

```
/etc/sssd-oidc/
├── config.toml       # 0644 root:root — no secrets
└── scim-token        # 0600 root:root — bearer token only (no newline)
```

Or for users who prefer a single file, the existing `bearer_token` in
`config.toml` continues to work, but `config.toml` must then be `0600`.

## Open Questions

- Should the token file be trimmed of trailing whitespace/newlines?
  (Yes — `trim()` the contents, matching how `bearer_token_file` works in
  Prometheus.)
- Should we also check the `client_secret` in `[oidc]` the same way?
  (Probably yes — same pattern, `client_secret_file` option.)
- Do we need the parent-directory ownership check like OpenSSH?
  (Probably not for v1 — `/etc/sssd-oidc/` is expected to be created by
  the package with correct permissions.)

## References

- OpenSSH key permission check: refuses keys with `mode & 0o077 != 0`
  (source: `authfile.c`, `sshkey_perm_ok()`)
- SSSD config permission check: `/etc/sssd/sssd.conf` must be `0600` owned
  by root — hard fail on startup
- WireGuard `wg-quick`: warns on world-accessible config but continues
- Prometheus `bearer_token_file`: reads token from file, no permission check
- Kubernetes Secret volumes: `defaultMode: 0644` by default, commonly
  overridden to `0400`
- Current code: `src/config.rs` lines 35–41 (`ScimConfig` struct),
  lines 137–157 (`Config::load()`)
