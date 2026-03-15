use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScimError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
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

/// SCIM 2.0 client using `reqwest::blocking`.
pub struct ScimClient {
    http: reqwest::blocking::Client,
    base_url: String,
    bearer_token: String,
}

impl ScimClient {
    pub fn new(base_url: &str, bearer_token: &str) -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer_token: bearer_token.to_string(),
        }
    }

    /// Look up a user by `userName`.
    pub fn get_user_by_name(&self, name: &str) -> Result<Option<ScimUser>, ScimError> {
        let url = format!("{}/Users?filter=userName eq \"{}\"", self.base_url, name);
        let resp: ListResponse<ScimUser> = self
            .http
            .get(&url)
            .bearer_auth(&self.bearer_token)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(resp.resources.into_iter().next())
    }

    /// Look up a user by SCIM `id`.
    pub fn get_user_by_id(&self, id: &str) -> Result<Option<ScimUser>, ScimError> {
        let url = format!("{}/Users/{}", self.base_url, id);
        let response = self.http.get(&url).bearer_auth(&self.bearer_token).send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let user: ScimUser = response.error_for_status()?.json()?;
        Ok(Some(user))
    }

    /// Look up a group by `displayName`.
    pub fn get_group_by_name(&self, name: &str) -> Result<Option<ScimGroup>, ScimError> {
        let url = format!(
            "{}/Groups?filter=displayName eq \"{}\"",
            self.base_url, name
        );
        let resp: ListResponse<ScimGroup> = self
            .http
            .get(&url)
            .bearer_auth(&self.bearer_token)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(resp.resources.into_iter().next())
    }

    /// Look up a group by SCIM `id`.
    pub fn get_group_by_id(&self, id: &str) -> Result<Option<ScimGroup>, ScimError> {
        let url = format!("{}/Groups/{}", self.base_url, id);
        let response = self.http.get(&url).bearer_auth(&self.bearer_token).send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let group: ScimGroup = response.error_for_status()?.json()?;
        Ok(Some(group))
    }

    /// List all users, paginating via SCIM `startIndex` + `count`.
    pub fn list_users(&self) -> Result<Vec<ScimUser>, ScimError> {
        self.paginate_list::<ScimUser>("Users")
    }

    /// List all groups, paginating via SCIM `startIndex` + `count`.
    pub fn list_groups(&self) -> Result<Vec<ScimGroup>, ScimError> {
        self.paginate_list::<ScimGroup>("Groups")
    }

    /// Generic paginated list for a SCIM resource type.
    fn paginate_list<T: serde::de::DeserializeOwned>(
        &self,
        resource: &str,
    ) -> Result<Vec<T>, ScimError> {
        let count = 100;
        let mut start_index = 1usize;
        let mut all = Vec::new();

        loop {
            let url = format!(
                "{}/{}?startIndex={}&count={}",
                self.base_url, resource, start_index, count
            );
            let resp: ListResponse<T> = self
                .http
                .get(&url)
                .bearer_auth(&self.bearer_token)
                .send()?
                .error_for_status()?
                .json()?;

            let fetched = resp.resources.len();
            all.extend(resp.resources);

            if all.len() >= resp.total_results || fetched == 0 {
                break;
            }
            start_index += fetched;
        }

        Ok(all)
    }
}
