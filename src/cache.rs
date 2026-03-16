use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;
use tracing::{debug, info, trace};

use crate::mapping::{IdRangeExhausted, resolve_id};
use crate::model::{Group, User};

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("UID/GID range exhausted — all slots occupied")]
    RangeExhausted,
    #[error("insecure permissions on cache {path}: {detail}")]
    InsecurePermissions { path: String, detail: String },
}

impl From<IdRangeExhausted> for CacheError {
    fn from(_: IdRangeExhausted) -> Self {
        Self::RangeExhausted
    }
}

/// SQLite-backed local cache for UID/GID reverse lookups.
pub struct Cache {
    conn: Connection,
    /// Cache entry TTL in seconds. Entries older than this are treated as misses.
    ttl_seconds: u64,
}

impl Cache {
    /// Open (or create) the cache database at the given path.
    ///
    /// On Unix, after opening the file the permissions are tightened to `0600`.
    /// If the file is not owned by root (on Linux) or has group/other bits set
    /// and cannot be corrected, the open is refused with
    /// [`CacheError::InsecurePermissions`].
    pub fn open(path: &str, ttl_seconds: u64) -> Result<Self, CacheError> {
        info!(path, ttl_seconds, "opening cache database");
        let conn = Connection::open(path)?;

        // The `:memory:` path is used in tests — skip permission checks.
        if path != ":memory:" {
            Self::harden_cache_file(Path::new(path))?;
        }
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS uid_cache (
                external_id TEXT PRIMARY KEY,
                login       TEXT NOT NULL,
                uid         INTEGER UNIQUE NOT NULL,
                gecos       TEXT NOT NULL DEFAULT '',
                home        TEXT NOT NULL DEFAULT '',
                shell       TEXT NOT NULL DEFAULT '',
                gid         INTEGER NOT NULL DEFAULT 0,
                active      INTEGER NOT NULL DEFAULT 1,
                cached_at   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS gid_cache (
                external_id TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                gid         INTEGER UNIQUE NOT NULL,
                cached_at   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_external_id TEXT NOT NULL,
                member_name       TEXT NOT NULL,
                PRIMARY KEY (group_external_id, member_name),
                FOREIGN KEY (group_external_id) REFERENCES gid_cache(external_id)
                    ON DELETE CASCADE
            );
            ",
        )?;
        Ok(Self { conn, ttl_seconds })
    }

    /// Enforce restrictive ownership and permissions on the cache file.
    ///
    /// Sets mode `0600` on the file. On Linux, also requires root ownership.
    /// Follows the same hardening pattern as `check_secret_file_permissions`
    /// in `config.rs`.
    #[cfg(unix)]
    fn harden_cache_file(path: &Path) -> Result<(), CacheError> {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let meta = fs::symlink_metadata(path).map_err(|e| CacheError::InsecurePermissions {
            path: path.display().to_string(),
            detail: format!("cannot stat file: {e}"),
        })?;

        if !meta.is_file() {
            return Err(CacheError::InsecurePermissions {
                path: path.display().to_string(),
                detail: "not a regular file".into(),
            });
        }

        // On Linux, refuse to use a cache file not owned by root.
        #[cfg(target_os = "linux")]
        if meta.uid() != 0 {
            return Err(CacheError::InsecurePermissions {
                path: path.display().to_string(),
                detail: format!(
                    "owned by uid {} but must be owned by root (uid 0)",
                    meta.uid()
                ),
            });
        }

        let mode = meta.mode() & 0o777;
        if mode != 0o600 {
            info!(
                path = %path.display(),
                current_mode = format!("{mode:04o}"),
                "tightening cache file permissions to 0600"
            );
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                CacheError::InsecurePermissions {
                    path: path.display().to_string(),
                    detail: format!(
                        "permissions {:04o} are too open and could not be corrected: {e}. \
                         Run: chmod 600 {}",
                        mode,
                        path.display()
                    ),
                }
            })?;
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn harden_cache_file(_path: &Path) -> Result<(), CacheError> {
        Ok(())
    }

    /// Open an in-memory cache (useful for tests).
    pub fn open_in_memory() -> Result<Self, CacheError> {
        Self::open(":memory:", 3600)
    }

    /// Resolve a collision-free UID for `external_id` using linear probing.
    ///
    /// Returns the existing UID if this `external_id` is already cached,
    /// otherwise probes for the first free slot in the UID range.
    pub fn resolve_uid(
        &self,
        external_id: &str,
        range_min: u32,
        range_size: u32,
    ) -> Result<u32, CacheError> {
        resolve_id(external_id, range_min, range_size, |candidate| {
            self.uid_owner(candidate, external_id)
        })
    }

    /// Resolve a collision-free GID for `external_id` using linear probing.
    pub fn resolve_gid(
        &self,
        external_id: &str,
        range_min: u32,
        range_size: u32,
    ) -> Result<u32, CacheError> {
        resolve_id(external_id, range_min, range_size, |candidate| {
            self.gid_owner(candidate, external_id)
        })
    }

    /// Check if a UID slot is taken.
    /// Returns `None` (free), `Some(true)` (ours), or `Some(false)` (other).
    fn uid_owner(&self, uid: u32, external_id: &str) -> Result<Option<bool>, CacheError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT external_id FROM uid_cache WHERE uid = ?1")?;
        let mut rows = stmt.query_map([uid], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(Ok(owner)) => Ok(Some(owner == external_id)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Check if a GID slot is taken.
    fn gid_owner(&self, gid: u32, external_id: &str) -> Result<Option<bool>, CacheError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT external_id FROM gid_cache WHERE gid = ?1")?;
        let mut rows = stmt.query_map([gid], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(Ok(owner)) => Ok(Some(owner == external_id)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Store a user in the cache.
    pub fn store_user(&self, user: &User) -> Result<(), CacheError> {
        trace!(name = user.name, uid = user.uid, "caching user");
        self.conn.execute(
            "INSERT OR REPLACE INTO uid_cache
                (external_id, login, uid, gecos, home, shell, gid, active, cached_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%s', 'now'))",
            (
                &user.external_id,
                &user.name,
                user.uid,
                &user.gecos,
                &user.home,
                &user.shell,
                user.gid,
                user.active,
            ),
        )?;
        Ok(())
    }

    /// Look up a user by UID from the cache (respects TTL).
    pub fn get_user_by_uid(&self, uid: u32) -> Result<Option<User>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, login, uid, gid, gecos, home, shell, active
             FROM uid_cache WHERE uid = ?1 AND cached_at > strftime('%s', 'now') - ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![uid, self.ttl_seconds], |row| {
            Ok(User {
                external_id: row.get(0)?,
                name: row.get(1)?,
                uid: row.get(2)?,
                gid: row.get(3)?,
                gecos: row.get(4)?,
                home: row.get(5)?,
                shell: row.get(6)?,
                active: row.get(7)?,
            })
        })?;
        match rows.next() {
            Some(row) => {
                trace!(uid, "cache hit for user by uid");
                Ok(Some(row?))
            }
            None => {
                trace!(uid, "cache miss for user by uid");
                Ok(None)
            }
        }
    }

    /// Look up a user by login name from the cache (respects TTL).
    pub fn get_user_by_name(&self, name: &str) -> Result<Option<User>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, login, uid, gid, gecos, home, shell, active
             FROM uid_cache WHERE login = ?1 AND cached_at > strftime('%s', 'now') - ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![name, self.ttl_seconds], |row| {
            Ok(User {
                external_id: row.get(0)?,
                name: row.get(1)?,
                uid: row.get(2)?,
                gid: row.get(3)?,
                gecos: row.get(4)?,
                home: row.get(5)?,
                shell: row.get(6)?,
                active: row.get(7)?,
            })
        })?;
        match rows.next() {
            Some(row) => {
                trace!(name, "cache hit for user by name");
                Ok(Some(row?))
            }
            None => {
                trace!(name, "cache miss for user by name");
                Ok(None)
            }
        }
    }

    /// Store a group in the cache, including its member list.
    pub fn store_group(&self, group: &Group) -> Result<(), CacheError> {
        trace!(name = group.name, gid = group.gid, "caching group");
        self.conn.execute(
            "INSERT OR REPLACE INTO gid_cache
                (external_id, name, gid, cached_at)
             VALUES (?1, ?2, ?3, strftime('%s', 'now'))",
            (&group.external_id, &group.name, group.gid),
        )?;
        self.conn.execute(
            "DELETE FROM group_members WHERE group_external_id = ?1",
            [&group.external_id],
        )?;
        for member in &group.members {
            self.conn.execute(
                "INSERT INTO group_members (group_external_id, member_name) VALUES (?1, ?2)",
                (&group.external_id, member),
            )?;
        }
        Ok(())
    }

    /// Look up a group by GID from the cache (respects TTL).
    pub fn get_group_by_gid(&self, gid: u32) -> Result<Option<Group>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, name, gid FROM gid_cache
             WHERE gid = ?1 AND cached_at > strftime('%s', 'now') - ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![gid, self.ttl_seconds], |row| {
            Ok(Group {
                external_id: row.get(0)?,
                name: row.get(1)?,
                gid: row.get(2)?,
                members: Vec::new(),
            })
        })?;
        match rows.next() {
            Some(row) => {
                trace!(gid, "cache hit for group by gid");
                let mut group = row?;
                group.members = self.get_group_members(&group.external_id)?;
                Ok(Some(group))
            }
            None => {
                trace!(gid, "cache miss for group by gid");
                Ok(None)
            }
        }
    }

    /// Look up a group by name from the cache (respects TTL).
    pub fn get_group_by_name(&self, name: &str) -> Result<Option<Group>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, name, gid FROM gid_cache
             WHERE name = ?1 AND cached_at > strftime('%s', 'now') - ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![name, self.ttl_seconds], |row| {
            Ok(Group {
                external_id: row.get(0)?,
                name: row.get(1)?,
                gid: row.get(2)?,
                members: Vec::new(),
            })
        })?;
        match rows.next() {
            Some(row) => {
                trace!(name, "cache hit for group by name");
                let mut group = row?;
                group.members = self.get_group_members(&group.external_id)?;
                Ok(Some(group))
            }
            None => {
                trace!(name, "cache miss for group by name");
                Ok(None)
            }
        }
    }

    /// Purge cache entries older than `ttl_seconds`.
    pub fn purge_expired(&self, ttl_seconds: u64) -> Result<(), CacheError> {
        debug!(ttl_seconds, "purging expired cache entries");
        self.conn.execute(
            "DELETE FROM group_members WHERE group_external_id IN
                (SELECT external_id FROM gid_cache
                 WHERE cached_at <= strftime('%s', 'now') - ?1)",
            [ttl_seconds],
        )?;
        self.conn.execute(
            "DELETE FROM gid_cache WHERE cached_at <= strftime('%s', 'now') - ?1",
            [ttl_seconds],
        )?;
        self.conn.execute(
            "DELETE FROM uid_cache WHERE cached_at <= strftime('%s', 'now') - ?1",
            [ttl_seconds],
        )?;
        Ok(())
    }

    /// Return all cached groups that contain `member_name` (respects TTL).
    ///
    /// Used for offline `initgroups` fallback: given a login name, find every
    /// group whose `group_members` row lists that name, then return their GIDs.
    pub fn get_groups_for_member(&self, member_name: &str) -> Result<Vec<Group>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT g.external_id, g.name, g.gid
             FROM gid_cache g
             JOIN group_members gm ON gm.group_external_id = g.external_id
             WHERE gm.member_name = ?1
               AND g.cached_at > strftime('%s', 'now') - ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![member_name, self.ttl_seconds], |row| {
            Ok(Group {
                external_id: row.get(0)?,
                name: row.get(1)?,
                gid: row.get(2)?,
                members: Vec::new(),
            })
        })?;
        let mut groups = Vec::new();
        for row in rows {
            let mut group = row?;
            group.members = self.get_group_members(&group.external_id)?;
            groups.push(group);
        }
        trace!(
            member_name,
            count = groups.len(),
            "cache lookup groups for member"
        );
        Ok(groups)
    }

    /// Load group members from the cache.
    fn get_group_members(&self, external_id: &str) -> Result<Vec<String>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT member_name FROM group_members WHERE group_external_id = ?1")?;
        let rows = stmt.query_map([external_id], |row| row.get(0))?;
        let mut members = Vec::new();
        for name in rows {
            members.push(name?);
        }
        Ok(members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_user() {
        let cache = Cache::open_in_memory().unwrap();
        let user = User {
            external_id: "abc-123".into(),
            name: "alice".into(),
            uid: 200_042,
            gid: 200_001,
            gecos: "Alice Smith".into(),
            home: "/home/alice".into(),
            shell: "/bin/bash".into(),
            active: true,
        };
        cache.store_user(&user).unwrap();

        let by_uid = cache.get_user_by_uid(200_042).unwrap().unwrap();
        assert_eq!(by_uid, user);

        let by_name = cache.get_user_by_name("alice").unwrap().unwrap();
        assert_eq!(by_name, user);

        assert!(cache.get_user_by_uid(999_999).unwrap().is_none());
    }

    #[test]
    fn round_trip_group() {
        let cache = Cache::open_in_memory().unwrap();
        let group = Group {
            external_id: "grp-456".into(),
            name: "engineering".into(),
            gid: 200_010,
            members: vec!["alice".into(), "bob".into()],
        };
        cache.store_group(&group).unwrap();

        let by_gid = cache.get_group_by_gid(200_010).unwrap().unwrap();
        assert_eq!(by_gid.name, "engineering");
        assert_eq!(by_gid.gid, 200_010);
        assert_eq!(by_gid.members, vec!["alice", "bob"]);

        let by_name = cache.get_group_by_name("engineering").unwrap().unwrap();
        assert_eq!(by_name.gid, 200_010);
        assert_eq!(by_name.members, vec!["alice", "bob"]);
    }

    #[test]
    fn purge_expired_removes_old_entries() {
        let cache = Cache::open_in_memory().unwrap();
        let user = User {
            external_id: "abc-123".into(),
            name: "alice".into(),
            uid: 200_042,
            gid: 200_001,
            gecos: "Alice Smith".into(),
            home: "/home/alice".into(),
            shell: "/bin/bash".into(),
            active: true,
        };
        cache.store_user(&user).unwrap();

        let group = Group {
            external_id: "grp-456".into(),
            name: "engineering".into(),
            gid: 200_010,
            members: vec!["alice".into()],
        };
        cache.store_group(&group).unwrap();

        // With TTL=0 everything is already expired
        cache.purge_expired(0).unwrap();

        assert!(cache.get_user_by_uid(200_042).unwrap().is_none());
        assert!(cache.get_group_by_gid(200_010).unwrap().is_none());
    }

    #[test]
    fn resolve_uid_returns_same_id_for_same_external_id() {
        let cache = Cache::open_in_memory().unwrap();
        let uid1 = cache.resolve_uid("user-aaa", 200_000, 200_000).unwrap();
        // Store a user so the cache knows this UID is taken by "user-aaa"
        cache
            .store_user(&User {
                external_id: "user-aaa".into(),
                name: "aaa".into(),
                uid: uid1,
                gid: 200_001,
                gecos: String::new(),
                home: "/home/aaa".into(),
                shell: "/bin/bash".into(),
                active: true,
            })
            .unwrap();
        // Same external_id should resolve to the same UID
        let uid2 = cache.resolve_uid("user-aaa", 200_000, 200_000).unwrap();
        assert_eq!(uid1, uid2);
    }

    #[test]
    fn resolve_uid_linear_probes_on_collision() {
        let cache = Cache::open_in_memory().unwrap();
        // Get the candidate UID for user-aaa
        let uid_aaa = cache.resolve_uid("user-aaa", 200_000, 200_000).unwrap();
        // Occupy that slot with user-aaa
        cache
            .store_user(&User {
                external_id: "user-aaa".into(),
                name: "aaa".into(),
                uid: uid_aaa,
                gid: 200_001,
                gecos: String::new(),
                home: "/home/aaa".into(),
                shell: "/bin/bash".into(),
                active: true,
            })
            .unwrap();

        // Now manually insert a *different* user at the same UID that user-bbb
        // would hash to, to force a collision. We do this by finding user-bbb's
        // natural hash and pre-occupying it.
        let natural_bbb = crate::mapping::id_to_uid("user-bbb", 200_000, 200_000);
        cache
            .store_user(&User {
                external_id: "blocker".into(),
                name: "blocker".into(),
                uid: natural_bbb,
                gid: 200_001,
                gecos: String::new(),
                home: "/home/blocker".into(),
                shell: "/bin/bash".into(),
                active: true,
            })
            .unwrap();

        // user-bbb should get a different UID (probed)
        let uid_bbb = cache.resolve_uid("user-bbb", 200_000, 200_000).unwrap();
        assert_ne!(uid_bbb, natural_bbb);
        assert!(uid_bbb >= 200_000 && uid_bbb < 400_000);
    }

    #[test]
    fn resolve_gid_handles_collision() {
        let cache = Cache::open_in_memory().unwrap();
        let gid_a = cache.resolve_gid("group-a", 300_000, 100).unwrap();
        cache
            .store_group(&Group {
                external_id: "group-a".into(),
                name: "alpha".into(),
                gid: gid_a,
                members: vec![],
            })
            .unwrap();

        // Occupy group-b's natural slot with group-a's data by inserting a
        // blocker at group-b's hash
        let natural_b = crate::mapping::id_to_uid("group-b", 300_000, 100);
        if natural_b != gid_a {
            cache
                .store_group(&Group {
                    external_id: "blocker".into(),
                    name: "blocker".into(),
                    gid: natural_b,
                    members: vec![],
                })
                .unwrap();
        }

        let gid_b = cache.resolve_gid("group-b", 300_000, 100).unwrap();
        assert_ne!(gid_b, natural_b);
        assert!(gid_b >= 300_000 && gid_b < 300_100);
    }

    #[test]
    fn get_groups_for_member_returns_matching_groups() {
        let cache = Cache::open_in_memory().unwrap();
        let eng = Group {
            external_id: "grp-eng".into(),
            name: "engineering".into(),
            gid: 200_010,
            members: vec!["alice".into(), "bob".into()],
        };
        let ops = Group {
            external_id: "grp-ops".into(),
            name: "operations".into(),
            gid: 200_020,
            members: vec!["alice".into(), "carol".into()],
        };
        let design = Group {
            external_id: "grp-des".into(),
            name: "design".into(),
            gid: 200_030,
            members: vec!["carol".into()],
        };
        cache.store_group(&eng).unwrap();
        cache.store_group(&ops).unwrap();
        cache.store_group(&design).unwrap();

        let alice_groups = cache.get_groups_for_member("alice").unwrap();
        let mut alice_gids: Vec<u32> = alice_groups.iter().map(|g| g.gid).collect();
        alice_gids.sort();
        assert_eq!(alice_gids, vec![200_010, 200_020]);

        let carol_groups = cache.get_groups_for_member("carol").unwrap();
        let mut carol_gids: Vec<u32> = carol_groups.iter().map(|g| g.gid).collect();
        carol_gids.sort();
        assert_eq!(carol_gids, vec![200_020, 200_030]);

        let nobody = cache.get_groups_for_member("nobody").unwrap();
        assert!(nobody.is_empty());
    }

    #[test]
    fn purge_expired_keeps_recent_entries() {
        let cache = Cache::open_in_memory().unwrap();
        let user = User {
            external_id: "abc-123".into(),
            name: "alice".into(),
            uid: 200_042,
            gid: 200_001,
            gecos: "Alice Smith".into(),
            home: "/home/alice".into(),
            shell: "/bin/bash".into(),
            active: true,
        };
        cache.store_user(&user).unwrap();

        // With a large TTL, entries should be kept
        cache.purge_expired(86400).unwrap();

        assert!(cache.get_user_by_uid(200_042).unwrap().is_some());
    }
}
