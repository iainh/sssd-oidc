pub mod mock_idp;

use std::io::Write;

use sssd_oidc::config::Config;
use tempfile::NamedTempFile;

/// Create a temporary config file pointing at the given mock server URLs.
/// Returns the temp file (keeps it alive) and the parsed Config.
pub fn test_config(scim_base_url: &str, oidc_issuer_url: &str) -> (NamedTempFile, Config) {
    let toml_content = format!(
        r#"
[scim]
base_url = "{scim_base_url}"
bearer_token = "test-bearer-token"

[oidc]
issuer_url = "{oidc_issuer_url}"
client_id = "test-client-id"

[mapping]
uid_range_min = 200000
uid_range_size = 200000
gid_range_min = 200000
gid_range_size = 200000

[user_defaults]
shell = "/bin/bash"
home_template = "/home/{{user}}"

[cache]
db_path = ":memory:"
"#
    );

    let mut f = NamedTempFile::new().expect("failed to create temp config file");
    f.write_all(toml_content.as_bytes())
        .expect("failed to write temp config");
    f.flush().expect("failed to flush temp config");

    let config = Config::load_from(f.path()).expect("failed to parse test config");
    (f, config)
}
