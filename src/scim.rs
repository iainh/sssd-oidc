use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

/// Characters that must be percent-encoded when used in a URL path segment.
/// Covers CONTROLS plus the RFC 3986 reserved sub-delimiters and gen-delimiters
/// that are not valid unencoded in a single path segment.
const PATH_SEGMENT_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'<')
    .add(b'>')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, Error)]
pub enum ScimError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("JSON deserialization failed: {0}")]
    Json(#[from] std::io::Error),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("group not found: {0}")]
    GroupNotFound(String),
}

/// Raw SCIM 2.0 user resource (RFC 7643).
#[derive(Debug, Clone, Deserialize)]
pub struct ScimUser {
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub groups: Vec<ScimGroupRef>,
}

/// A group reference embedded in a SCIM user resource.
#[derive(Debug, Clone, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(rename = "display", default)]
    pub display: Option<String>,
}

/// Raw SCIM 2.0 group resource.
#[derive(Debug, Clone, Deserialize)]
pub struct ScimGroup {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimMemberRef>,
}

/// A member reference embedded in a SCIM group resource.
#[derive(Debug, Clone, Deserialize)]
pub struct ScimMemberRef {
    pub value: String,
    #[serde(rename = "display", default)]
    pub display: Option<String>,
}

/// SCIM list response wrapper.
#[derive(Debug, Deserialize)]
struct ListResponse<T> {
    #[serde(rename = "totalResults", default)]
    total_results: usize,
    #[serde(rename = "Resources")]
    #[serde(default = "Vec::new")]
    resources: Vec<T>,
}

/// Escape a value for use in a SCIM 2.0 filter expression (RFC 7644 §3.4.2.2).
/// Backslash-escapes `\` and `"` characters within the quoted string.
fn escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// SCIM 2.0 client using `ureq`.
pub struct ScimClient {
    http: ureq::Agent,
    base_url: String,
    bearer_token: String,
}

impl ScimClient {
    pub fn new(base_url: &str, bearer_token: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build();
        let http: ureq::Agent = config.into();
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer_token: bearer_token.to_string(),
        }
    }

    fn auth_header_value(&self) -> String {
        format!("Bearer {}", self.bearer_token)
    }

    /// Look up a user by `userName`.
    pub fn get_user_by_name(&self, name: &str) -> Result<Option<ScimUser>, ScimError> {
        debug!(name, "SCIM user lookup by name");
        let escaped = escape_filter_value(name);
        let filter = format!("userName eq \"{escaped}\"");
        let url = format!("{}/Users", self.base_url);
        let resp: ListResponse<ScimUser> = self
            .http
            .get(&url)
            .query_pairs([("filter", &filter)])
            .header("Authorization", &self.auth_header_value())
            .call()?
            .body_mut()
            .read_json()?;
        Ok(resp.resources.into_iter().next())
    }

    /// Look up a user by SCIM `id`.
    pub fn get_user_by_id(&self, id: &str) -> Result<Option<ScimUser>, ScimError> {
        debug!(id, "SCIM user lookup by id");
        let encoded_id = utf8_percent_encode(id, PATH_SEGMENT_ENCODE);
        let url = format!("{}/Users/{}", self.base_url, encoded_id);
        match self
            .http
            .get(&url)
            .header("Authorization", &self.auth_header_value())
            .call()
        {
            Ok(mut response) => {
                let user: ScimUser = response.body_mut().read_json()?;
                Ok(Some(user))
            }
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Look up a group by `displayName`.
    pub fn get_group_by_name(&self, name: &str) -> Result<Option<ScimGroup>, ScimError> {
        debug!(name, "SCIM group lookup by name");
        let escaped = escape_filter_value(name);
        let filter = format!("displayName eq \"{escaped}\"");
        let url = format!("{}/Groups", self.base_url);
        let resp: ListResponse<ScimGroup> = self
            .http
            .get(&url)
            .query_pairs([("filter", &filter)])
            .header("Authorization", &self.auth_header_value())
            .call()?
            .body_mut()
            .read_json()?;
        Ok(resp.resources.into_iter().next())
    }

    /// Look up a group by SCIM `id`.
    pub fn get_group_by_id(&self, id: &str) -> Result<Option<ScimGroup>, ScimError> {
        debug!(id, "SCIM group lookup by id");
        let encoded_id = utf8_percent_encode(id, PATH_SEGMENT_ENCODE);
        let url = format!("{}/Groups/{}", self.base_url, encoded_id);
        match self
            .http
            .get(&url)
            .header("Authorization", &self.auth_header_value())
            .call()
        {
            Ok(mut response) => {
                let group: ScimGroup = response.body_mut().read_json()?;
                Ok(Some(group))
            }
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all users, paginating via SCIM `startIndex` + `count`.
    pub fn list_users(&self) -> Result<Vec<ScimUser>, ScimError> {
        debug!("SCIM listing all users");
        self.paginate_list::<ScimUser>("Users")
    }

    /// List all groups, paginating via SCIM `startIndex` + `count`.
    pub fn list_groups(&self) -> Result<Vec<ScimGroup>, ScimError> {
        debug!("SCIM listing all groups");
        self.paginate_list::<ScimGroup>("Groups")
    }

    /// Check if the SCIM endpoint is reachable (health check).
    /// Makes a lightweight request to the Users endpoint with count=0.
    pub fn is_online(&self) -> bool {
        debug!("SCIM health check");
        let url = format!("{}/Users", self.base_url);
        let online = self
            .http
            .get(&url)
            .query_pairs([("count", "0")])
            .header("Authorization", &self.auth_header_value())
            .call()
            .is_ok();
        debug!(online, "SCIM health check result");
        online
    }

    /// Generic paginated list for a SCIM resource type.
    ///
    /// Limits total pages to `MAX_PAGINATION_PAGES` to guard against servers
    /// that return inconsistent `totalResults` or ignore `startIndex`.
    fn paginate_list<T: serde::de::DeserializeOwned>(
        &self,
        resource: &str,
    ) -> Result<Vec<T>, ScimError> {
        const MAX_PAGINATION_PAGES: usize = 1_000;
        let count = 100;
        let mut start_index = 1usize;
        let mut all = Vec::new();
        let mut complete = false;

        for _page in 0..MAX_PAGINATION_PAGES {
            let url = format!("{}/{}", self.base_url, resource);
            let start_str = start_index.to_string();
            let count_str = count.to_string();
            let resp: ListResponse<T> = self
                .http
                .get(&url)
                .query_pairs([
                    ("startIndex", start_str.as_str()),
                    ("count", count_str.as_str()),
                ])
                .header("Authorization", &self.auth_header_value())
                .call()?
                .body_mut()
                .read_json()?;

            let fetched = resp.resources.len();
            all.extend(resp.resources);

            if all.len() >= resp.total_results || fetched == 0 {
                complete = true;
                break;
            }
            start_index += fetched;
        }

        if !complete {
            warn!(
                count = all.len(),
                resource,
                max_pages = MAX_PAGINATION_PAGES,
                "SCIM pagination hit page limit — results may be incomplete"
            );
        }

        debug!(count = all.len(), resource, "SCIM pagination complete");
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_value_handles_plain_string() {
        assert_eq!(escape_filter_value("alice"), "alice");
    }

    #[test]
    fn escape_filter_value_escapes_quotes() {
        assert_eq!(escape_filter_value(r#"al"ice"#), r#"al\"ice"#);
    }

    #[test]
    fn escape_filter_value_escapes_backslashes() {
        assert_eq!(escape_filter_value(r"al\ice"), r"al\\ice");
    }

    #[test]
    fn escape_filter_value_escapes_both() {
        assert_eq!(escape_filter_value(r#"a\"b"#), r#"a\\\"b"#);
    }
}
