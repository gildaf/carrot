use std::env::var as env_var;
use std::path::PathBuf;

use dirs::home_dir;
use rusoto_core::credential::ProfileProvider;
use rusoto_core::Region;

pub fn regions() -> &'static [Region] {
    &[
        Region::ApNortheast1,
        Region::ApNortheast2,
        Region::ApSouth1,
        Region::ApSoutheast1,
        Region::ApSoutheast2,
        Region::CaCentral1,
        Region::EuCentral1,
        Region::EuWest1,
        Region::EuWest2,
        Region::EuWest3,
        Region::SaEast1,
        Region::UsEast1,
        Region::UsEast2,
        Region::UsWest1,
        Region::UsWest2,
    ]
}

fn default_aws_creds_location() -> Result<PathBuf, &'static str> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("credentials");
            Ok(home_path)
        }
        None => Err("Failed to determine home directory."),
    }
}

fn aws_creds_location() -> Result<PathBuf, &'static str> {
    let name = "AWS_CREDENTIALS";
    match env_var(name) {
        Ok(ref value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => default_aws_creds_location(),
    }
}

pub fn profile_provider() -> ProfileProvider {
    let name = "AWS_PROFILE";
    let profile_name = match env_var(name) {
        Ok(value) => value,
        _ => "default".to_string(),
    };
    ProfileProvider::with_configuration(aws_creds_location().unwrap(), profile_name)
}
