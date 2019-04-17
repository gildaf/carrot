#[macro_use] extern crate log;
extern crate env_logger;
extern crate serde_json;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_cloudtrail;

extern crate futures;
extern crate tokio;
extern crate chrono;


use std::env::var as env_var;
use tokio::prelude::*;
use chrono::prelude::*;
use std::{str, fmt};

use std::path::PathBuf;
use dirs::home_dir;
use rusoto_core::{Region, HttpClient};
use rusoto_core::credential::ProfileProvider;
use rusoto_ec2::{
    Ec2Client,
    DescribeVpcsError,
};
use rusoto_cloudtrail::{
    CloudTrailClient,
    LookupEventsError,
    Event,
};

mod vpc_stream;
mod events_stream;
use vpc_stream::VpcStream;
use events_stream::EventStream;


fn regions() ->  &'static [Region]{
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
    ]
}


fn default_aws_creds_location() -> Result<PathBuf, &'static str> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("credentials");
            Ok(home_path)
        }
        None => Err(
            "Failed to determine home directory.",
        ),
    }
}


fn aws_creds_location() -> Result<PathBuf, &'static str> {
    let name = "AWS_CREDENTIALS";
    match env_var(name) {
        Ok(ref value) if !value.is_empty() => {
            Ok(PathBuf::from(value))
        }
        _ => default_aws_creds_location()
    }

}


fn profile_provider() -> ProfileProvider {
    let name = "AWS_PROFILE";
    let profile_name = match env_var(name) {
        Ok(value)  => value,
        _ => "default".to_string()
    };
    ProfileProvider::with_configuration(aws_creds_location().unwrap(), profile_name)
}


fn get_events_client(region: Region) -> CloudTrailClient {
    let client = CloudTrailClient::new_with(
        HttpClient::new().unwrap(),
        profile_provider(),
        region);
    client
}


fn get_ec2_client(region: Region) -> Ec2Client {
    let client = Ec2Client::new_with(
        HttpClient::new().unwrap(),
        profile_provider(),
        region
    );
    client
}


type VpcID = String;

struct VpcInfo {
    vpc_id: VpcID,
    region: Region,
    creation_time: Option<f64>,
    created_by: Option<String>,
}


impl VpcInfo {
    fn new(vpc_id: VpcID, region: Region) -> VpcInfo {
        VpcInfo{
            vpc_id,
            region,
            creation_time: None,
            created_by: None,
        }
    }

    fn from_events(vpc_id: VpcID, region: Region, events: Vec<Event>) -> VpcInfo {
        let mut vpc_info = VpcInfo::new(vpc_id, region);
        for event in events {
            let Event{ event_name, username, event_time, ..} = event ;
            if let Some(name) = event_name {
                if name == "CreateVpc" {
                    vpc_info.created_by = username;
                    vpc_info.creation_time = event_time;
                }
            }
        }
        vpc_info
    }
}

impl fmt::Debug for VpcInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let creation_time = match &self.creation_time {
            &Some(time) => {
                NaiveDateTime::from_timestamp(time.round() as i64, 0).to_string()
            }
            None => "Unknown".to_string()
        };
        let created_by= match &self.created_by {
            &Some(ref username) => {
                username.as_str()
            }
            None => "Unknown"
        };

        write!(f,
               "vpc: {} ({:?}), created by {} on {}",
               self.vpc_id.as_str(), self.region, created_by, creation_time
        )
    }
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


//        pub type Poll<T, E> = Result<Async<T>, E>;
fn get_vpc_info(region: Region, vpc_id: String) -> impl Future<Item=VpcInfo, Error=LookupEventsError> {
    let client = get_events_client(region.clone());
    let events = EventStream::all_per_vpc(client, vpc_id.clone());
    let x =  events
        .filter(
            |event| { event.event_name.as_ref().unwrap().contains("CreateVpc")}
        ).collect();
    info!("starting to collect streams for {:?}", &vpc_id);
    let y =  x.map( move |events: Vec<Event>| { VpcInfo::from_events(vpc_id, region, events) });
    y
}


fn print_vpcs(region: Region) {
    let client = get_ec2_client(region.clone());
    let x = VpcStream::all(client).for_each(
         move |vpc| {
                let z =
                    get_vpc_info(region.clone(), vpc.vpc_id.unwrap())
                    .map_err(|e| { handle_error(e); } )
                    .map(| vpc_info: VpcInfo | { println!("{:?}", vpc_info); });
                tokio::spawn(z);
                Ok(())
         }
    );
    let y = x.map_err(handle_vpcs_error);
    tokio::run(y);
}

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    warn!("starting");
    for region in regions(){
        print_vpcs(region.clone());
    }
    warn!("done");
}