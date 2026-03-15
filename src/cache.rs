use rusqlite::Connection;
use thiserror::Error;

use crate::model::{Group, User};

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// SQLite-backed local cache for UID/GID reverse lookups.
pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Open (or create) the cache database at the given path.
    pub fn open(path: &str) -> Result<Self, CacheError> {
        let conn = Connection::open(path)?;
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
        Ok(Self { conn })
    }

    /// Open an in-memory cache (useful for tests).
    pub fn open_in_memory() -> Result<Self, CacheError> {
        Self::open(":memory:")
    }

    /// Store a user in the cache.
    pub fn store_user(&self, user: &User) -> Result<(), CacheError> {
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

    /// Look up a user by UID from the cache.
    pub fn get_user_by_uid(&self, uid: u32) -> Result<Option<User>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, login, uid, gid, gecos, home, shell, active
             FROM uid_cache WHERE uid = ?1",
        )?;
        let mut rows = stmt.query_map([uid], |row| {
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
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Look up a user by login name from the cache.
    pub fn get_user_by_name(&self, name: &str) -> Result<Option<User>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT external_id, login, uid, gid, gecos, home, shell, active
             FROM uid_cache WHERE login = ?1",
        )?;
        let mut rows = stmt.query_map([name], |row| {
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
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Store a group in the cache, including its member list.
    pub fn store_group(&self, group: &Group) -> Result<(), CacheError> {
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

    /// Look up a group by GID from the cache.
    pub fn get_group_by_gid(&self, gid: u32) -> Result<Option<Group>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT external_id, name, gid FROM gid_cache WHERE gid = ?1")?;
        let mut rows = stmt.query_map([gid], |row| {
            Ok(Group {
                external_id: row.get(0)?,
                name: row.get(1)?,
                gid: row.get(2)?,
                members: Vec::new(),
            })
        })?;
        match rows.next() {
            Some(row) => {
                let mut group = row?;
                group.members = self.get_group_members(&group.external_id)?;
                Ok(Some(group))
            }
            None => Ok(None),
        }
    }

    /// Look up a group by name from the cache.
    pub fn get_group_by_name(&self, name: &str) -> Result<Option<Group>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT external_id, name, gid FROM gid_cache WHERE name = ?1")?;
        let mut rows = stmt.query_map([name], |row| {
            Ok(Group {
                external_id: row.get(0)?,
                name: row.get(1)?,
                gid: row.get(2)?,
                members: Vec::new(),
            })
        })?;
        match rows.next() {
            Some(row) => {
                let mut group = row?;
                group.members = self.get_group_members(&group.external_id)?;
                Ok(Some(group))
            }
            None => Ok(None),
        }
    }

    /// Purge cache entries older than `ttl_seconds`.
    pub fn purge_expired(&self, ttl_seconds: u64) -> Result<(), CacheError> {
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
