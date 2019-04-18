#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rusoto_cloudtrail;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate serde_json;

extern crate chrono;
extern crate futures;
extern crate tokio;

use std::env::var as env_var;
use std::str;
use tokio::prelude::*;

use dirs::home_dir;
use rusoto_cloudtrail::{CloudTrailClient, Event, LookupEventsError};
use rusoto_core::credential::ProfileProvider;
use rusoto_core::{HttpClient, Region};
use rusoto_ec2::{DescribeVpcsError, Ec2Client};
use std::path::PathBuf;

mod events_stream;
mod vpc_info;
mod vpc_stream;
use events_stream::EventStream;
use vpc_info::VpcInfo;
use vpc_stream::VpcStream;

fn regions() -> &'static [Region] {
    return &[
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
    ];
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

fn profile_provider() -> ProfileProvider {
    let name = "AWS_PROFILE";
    let profile_name = match env_var(name) {
        Ok(value) => value,
        _ => "default".to_string(),
    };
    ProfileProvider::with_configuration(aws_creds_location().unwrap(), profile_name)
}

fn get_events_client(region: Region) -> CloudTrailClient {
    let client = CloudTrailClient::new_with(HttpClient::new().unwrap(), profile_provider(), region);
    client
}

fn get_ec2_client(region: Region) -> Ec2Client {
    let client = Ec2Client::new_with(HttpClient::new().unwrap(), profile_provider(), region);
    client
}

pub fn handle_error(e: LookupEventsError) {
    if let LookupEventsError::Unknown(http_error) = e {
        let s = str::from_utf8(&http_error.body).unwrap();
        println!("LookupEventsError : {:?}, {:?}", http_error.status, s);
    } else {
        println!("Other events error {:?}", e);
    };
}

pub fn handle_vpcs_error(e: DescribeVpcsError) {
    if let DescribeVpcsError::Unknown(http_error) = e {
        let s = str::from_utf8(&http_error.body).unwrap();
        error!("LookupEventsError : {:?}, {:?}", http_error.status, s);
    } else {
        error!("Other vpcs error {:?}", e);
    };
}

fn get_vpc_info(
    region: Region,
    vpc_id: String,
) -> impl Future<Item = VpcInfo, Error = LookupEventsError> {
    let client = get_events_client(region.clone());
    let events_stream = EventStream::all_per_vpc(client, vpc_id.clone());
    let relevant_events = events_stream
        .filter(|event| event.event_name.as_ref().unwrap().contains("CreateVpc"))
        .collect();
    info!("starting to collect streams for {:?}", &vpc_id);
    let vpc_info =
        relevant_events.map(move |events: Vec<Event>| VpcInfo::from_events(vpc_id, region, events));
    vpc_info
}

fn get_vpcs_info(region: Region) {
    let client = get_ec2_client(region.clone());
    let x = VpcStream::all(client).for_each(move |vpc| {
        let z = get_vpc_info(region.clone(), vpc.vpc_id.unwrap())
            .map_err(|e| {
                handle_error(e);
            })
            .map(|vpc_info: VpcInfo| {
                println!("{:?}", vpc_info);
            });
        tokio::spawn(z);
        Ok(())
    });
    let y = x.map_err(handle_vpcs_error);
    tokio::run(y);
}

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    warn!("starting");
    for region in regions() {
        get_vpcs_info(region.clone());
    }
    warn!("done");
}
