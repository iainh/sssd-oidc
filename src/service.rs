use thiserror::Error;
use tracing::{debug, info, warn};

use crate::cache::Cache;
use crate::config::Config;
use crate::mapping::IdRangeExhausted;
use crate::model::{Group, User};
use crate::scim::{ScimClient, ScimError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("SCIM error: {0}")]
    Scim(#[from] ScimError),
    #[error("cache error: {0}")]
    Cache(#[from] crate::cache::CacheError),
    #[error("UID/GID range exhausted — all slots occupied")]
    RangeExhausted,
}

impl From<IdRangeExhausted> for ServiceError {
    fn from(_: IdRangeExhausted) -> Self {
        Self::RangeExhausted
    }
}

/// Maximum length for user/group name lookups (matches `LOGIN_NAME_MAX`).
const MAX_NAME_LEN: usize = 256;

/// Façade used by NSS and PAM modules to resolve users and groups.
pub struct Service {
    scim: ScimClient,
    cache: Cache,
    config: Config,
}

impl Service {
    pub fn new(config: Config, scim: ScimClient, cache: Cache) -> Self {
        let ttl = config.cache.ttl_seconds;
        if let Err(e) = cache.purge_expired(ttl) {
            warn!(error = %e, "failed to purge expired cache entries on startup");
        }
        Self {
            scim,
            cache,
            config,
        }
    }

    /// Look up a user by login name. Tries SCIM first, falls back to cache.
    pub fn lookup_user_by_name(&self, name: &str) -> Result<Option<User>, ServiceError> {
        if name.len() > MAX_NAME_LEN {
            debug!(name_len = name.len(), "rejecting oversized user name");
            return Ok(None);
        }
        debug!(name, "looking up user by name");
        match self.scim.get_user_by_name(name) {
            Ok(Some(scim_user)) => {
                let user = self.scim_user_to_model(&scim_user)?;
                self.cache.store_user(&user)?;
                debug!(name, uid = user.uid, "user resolved via SCIM");
                Ok(Some(user))
            }
            Ok(None) => {
                debug!(name, "user not found in SCIM, checking cache");
                Ok(self.cache.get_user_by_name(name)?)
            }
            Err(e) => {
                warn!(name, error = %e, "SCIM lookup failed, falling back to cache");
                Ok(self.cache.get_user_by_name(name)?)
            }
        }
    }

    /// Look up a user by UID. Checks cache first (reverse lookup), then SCIM.
    pub fn lookup_user_by_uid(&self, uid: u32) -> Result<Option<User>, ServiceError> {
        debug!(uid, "looking up user by uid");
        if let Some(cached) = self.cache.get_user_by_uid(uid)? {
            return Ok(Some(cached));
        }
        // UID reverse lookup requires the cache to have been populated by a
        // prior name-based lookup. Without a mapping table from UID→external_id,
        // we cannot query SCIM by UID directly.
        Ok(None)
    }

    /// Look up a group by name.
    pub fn lookup_group_by_name(&self, name: &str) -> Result<Option<Group>, ServiceError> {
        if name.len() > MAX_NAME_LEN {
            debug!(name_len = name.len(), "rejecting oversized group name");
            return Ok(None);
        }
        debug!(name, "looking up group by name");
        match self.scim.get_group_by_name(name) {
            Ok(Some(scim_group)) => {
                let group = self.scim_group_to_model(&scim_group)?;
                self.cache.store_group(&group)?;
                Ok(Some(group))
            }
            Ok(None) => Ok(self.cache.get_group_by_name(name)?),
            Err(e) => {
                warn!(name, error = %e, "SCIM group lookup failed, falling back to cache");
                Ok(self.cache.get_group_by_name(name)?)
            }
        }
    }

    /// Look up a group by GID. Checks cache first.
    pub fn lookup_group_by_gid(&self, gid: u32) -> Result<Option<Group>, ServiceError> {
        debug!(gid, "looking up group by gid");
        if let Some(cached) = self.cache.get_group_by_gid(gid)? {
            return Ok(Some(cached));
        }
        Ok(None)
    }

    /// List all users from SCIM, convert to models, and cache each.
    pub fn list_all_users(&self) -> Result<Vec<User>, ServiceError> {
        let scim_users = self.scim.list_users()?;
        let mut users = Vec::with_capacity(scim_users.len());
        for su in &scim_users {
            let user = self.scim_user_to_model(su)?;
            self.cache.store_user(&user)?;
            users.push(user);
        }
        info!(count = users.len(), "listed all users from SCIM");
        Ok(users)
    }

    /// List all groups from SCIM, convert to models, and cache each.
    pub fn list_all_groups(&self) -> Result<Vec<Group>, ServiceError> {
        let scim_groups = self.scim.list_groups()?;
        let mut groups = Vec::with_capacity(scim_groups.len());
        for sg in &scim_groups {
            let group = self.scim_group_to_model(sg)?;
            self.cache.store_group(&group)?;
            groups.push(group);
        }
        info!(count = groups.len(), "listed all groups from SCIM");
        Ok(groups)
    }

    /// Check if a user is active. Tries SCIM first, falls back to cache.
    /// Cached users are assumed active unless explicitly marked inactive.
    pub fn check_user_active(&self, name: &str) -> Result<bool, ServiceError> {
        if name.len() > MAX_NAME_LEN {
            return Ok(false);
        }
        match self.scim.get_user_by_name(name) {
            Ok(Some(scim_user)) => {
                let user = self.scim_user_to_model(&scim_user)?;
                self.cache.store_user(&user)?;
                debug!(name, active = user.active, "user active status");
                Ok(user.active)
            }
            Ok(None) => Ok(false), // user not found → not active
            Err(e) => {
                warn!(name, error = %e, "SCIM active check failed, falling back to cache");
                match self.cache.get_user_by_name(name)? {
                    Some(user) => Ok(user.active),
                    None => Ok(false),
                }
            }
        }
    }

    /// Check if the SCIM backend is reachable.
    pub fn is_online(&self) -> bool {
        self.scim.is_online()
    }

    /// Look up all groups a user belongs to by login name.
    /// Returns the GIDs from the user's SCIM `groups` attribute.
    pub fn lookup_groups_for_user(&self, name: &str) -> Result<Vec<u32>, ServiceError> {
        if name.len() > MAX_NAME_LEN {
            return Ok(Vec::new());
        }
        let mc = &self.config.mapping;
        match self.scim.get_user_by_name(name) {
            Ok(Some(scim_user)) => {
                let user = self.scim_user_to_model(&scim_user)?;
                self.cache.store_user(&user)?;
                let mut gids = Vec::with_capacity(scim_user.groups.len());
                for g in &scim_user.groups {
                    gids.push(self.cache.resolve_gid(
                        &g.value,
                        mc.gid_range_min,
                        mc.gid_range_size,
                    )?);
                }
                Ok(gids)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => {
                warn!(name, error = %e, "SCIM group membership lookup failed, falling back to cache");
                let cached = self.cache.get_groups_for_member(name)?;
                Ok(cached.into_iter().map(|g| g.gid).collect())
            }
        }
    }

    fn scim_user_to_model(&self, scim_user: &crate::scim::ScimUser) -> Result<User, ServiceError> {
        let mc = &self.config.mapping;
        let uid = self
            .cache
            .resolve_uid(&scim_user.id, mc.uid_range_min, mc.uid_range_size)?;
        let gid_external = if let Some(first_group) = scim_user.groups.first() {
            &first_group.value
        } else {
            &scim_user.id
        };
        let gid = self
            .cache
            .resolve_gid(gid_external, mc.gid_range_min, mc.gid_range_size)?;
        let home = self
            .config
            .user_defaults
            .home_template
            .replace("{user}", &scim_user.user_name);
        Ok(User {
            external_id: scim_user.id.clone(),
            name: scim_user.user_name.clone(),
            uid,
            gid,
            gecos: scim_user.display_name.clone().unwrap_or_default(),
            home,
            shell: self.config.user_defaults.shell.clone(),
            active: scim_user.active.unwrap_or(true),
        })
    }

    fn scim_group_to_model(
        &self,
        scim_group: &crate::scim::ScimGroup,
    ) -> Result<Group, ServiceError> {
        let mc = &self.config.mapping;
        let gid = self
            .cache
            .resolve_gid(&scim_group.id, mc.gid_range_min, mc.gid_range_size)?;
        let members = scim_group
            .members
            .iter()
            .filter_map(|m| m.display.clone())
            .collect();
        Ok(Group {
            external_id: scim_group.id.clone(),
            name: scim_group.display_name.clone(),
            gid,
            members,
        })
    }
}
