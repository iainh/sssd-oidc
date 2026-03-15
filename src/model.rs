use serde::{Deserialize, Serialize};

/// A resolved POSIX user, ready to be packed into `struct passwd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// OIDC subject / SCIM id (the stable external identifier).
    pub external_id: String,
    /// Login name (SCIM `userName`).
    pub name: String,
    /// Mapped local UID.
    pub uid: u32,
    /// Primary group GID.
    pub gid: u32,
    /// GECOS / display name.
    pub gecos: String,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
    /// Whether the user account is active (from SCIM `active` field).
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

/// A resolved POSIX group, ready to be packed into `struct group`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// SCIM group id.
    pub external_id: String,
    /// Group name (SCIM `displayName`).
    pub name: String,
    /// Mapped local GID.
    pub gid: u32,
    /// Login names of group members.
    pub members: Vec<String>,
}
