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

use future::lazy;
use std::env::var as env_var;
use std::str;
use tokio::prelude::*;
use tokio::sync::mpsc::{channel, Sender};

use dirs::home_dir;
use rusoto_cloudtrail::{CloudTrailClient, Event, LookupEventsError};
use rusoto_core::credential::ProfileProvider;
use rusoto_core::{HttpClient, Region};
use rusoto_ec2::{DescribeVpcsError, Ec2Client, Vpc};
use std::path::PathBuf;

mod events_stream;
mod vpc_info;
mod vpc_stream;
use events_stream::EventStream;
use vpc_info::VpcInfo;
use vpc_stream::VpcStream;

fn regions() -> &'static [Region] {
//    &[
//        Region::ApNortheast1,
//        Region::ApNortheast2,
//        Region::ApSouth1,
//        Region::ApSoutheast1,
//        Region::ApSoutheast2,
//        Region::CaCentral1,
//        Region::EuCentral1,
//        Region::EuWest1,
//        Region::EuWest2,
//        Region::EuWest3,
//        Region::SaEast1,
//        Region::UsEast1,
//        Region::UsEast2,
//        Region::UsWest1,
//        Region::UsWest2,
//    ]
    &[Region::UsEast1]
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
    CloudTrailClient::new_with(HttpClient::new().unwrap(), profile_provider(), region)
}

fn get_ec2_client(region: Region) -> Ec2Client {
    Ec2Client::new_with(HttpClient::new().unwrap(), profile_provider(), region)
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

fn load_vpc_info(region: Region, vpc_id: String) -> impl Future<Item = VpcInfo, Error = ()> {
    let client = get_events_client(region.clone());
    let events_stream = EventStream::all_per_vpc(client, vpc_id.clone());
    let relevant_events = events_stream
        .map_err(|e| {
            handle_error(e);
        })
        .filter(|event| event.event_name.as_ref().unwrap().contains("CreateVpc"))
        .collect();
    info!("starting to collect streams for {:?}", &vpc_id);

    relevant_events.map(move |events: Vec<Event>| VpcInfo::from_events(vpc_id, region, events))
}

fn collect_vpcs_info(region: Region, tx: Sender<VpcInfo>) -> impl Future<Item = (), Error = DescribeVpcsError> {

    let client = get_ec2_client(region.clone());
    let vpc_to_vpc_info = move |vpc: Vpc| {
        let tx = tx.clone();
        let vpc_id = vpc.vpc_id.unwrap();
        load_vpc_info(region.clone(), vpc_id)
            .and_then(|vpc_info: VpcInfo| {
                tx.send(vpc_info)
                    .map(|e| {debug!("good {:?}", e); })
                    .map_err(|e| { debug!("sender failed {:?}", e); })
            })
            .map_err(|_e| {error!("failure");} )
    };
    VpcStream::all(client).for_each(move |vpc| {
        tokio::spawn(vpc_to_vpc_info(vpc));
        Ok(())
    })
}

use std::collections::HashMap;
fn get_all_info() -> impl Future<Item = (), Error = ()> {
    let (tx, rx) = channel::<VpcInfo>(100);
    regions().iter().for_each(|region| {
        let vpcs_future = collect_vpcs_info(region.clone(), tx.clone()).map_err(handle_vpcs_error);
        tokio::spawn(vpcs_future);
    });


//    let mut knowns :HashMap<String, Vec<VpcInfo>> = HashMap::new();
    rx.for_each(|value| {
        println!("2. VpcInfo = {:?}", value);
        Ok(())
    })
    .map_err(|e| {error!("reciever failed!! {:?}", e)})
}

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    warn!("starting");
    tokio::run(lazy(get_all_info));
    warn!("done");
}
