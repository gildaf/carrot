#[macro_use] extern crate log;
extern crate env_logger;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_cloudtrail;

extern crate futures;
extern crate tokio;
extern crate chrono;
//extern crate rusoto_sts;


use std::env::var as env_var;
use tokio::prelude::*;
use chrono::prelude::*;
use std::{str, fmt};

use std::collections::HashMap;
use std::path::PathBuf;
use futures::lazy;

use dirs::home_dir;
use rusoto_core::{Region, HttpClient};
use rusoto_core::credential::ProfileProvider;
use rusoto_ec2::{
    Ec2Client, Ec2,
    DescribeVpcsRequest, DescribeVpcsResult, DescribeVpcsError,
};
use rusoto_cloudtrail::{
    CloudTrailClient,
    CloudTrail,
    LookupEventsRequest,
    LookupEventsError,
    LookupAttribute,
    Event
};
mod vpc_stream;
use vpc_stream::VpcStream;
//use rusoto_sts::{StsClient, StsAssumeRoleSessionCredentialsProvider};


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


fn vpc_events_request(vpc_id: String) -> LookupEventsRequest {
    let attrs = vec![
        LookupAttribute{
            attribute_key: "ResourceName".to_string(),
            attribute_value: vpc_id,
        }
    ];
    let request = LookupEventsRequest {
        end_time: None,
        lookup_attributes: Some(attrs),
        max_results: None,
        next_token: None,
        start_time: None,
    };
    request
}


fn handle_events(events: Vec<Event>, vpc_id: String, region: Region) {
//    "CreateVpc"
    let name_to_event: HashMap<String, Event> = events.into_iter()
        .map(|event| (event.event_name.clone().unwrap(), event)).collect();
    match name_to_event.get("CreateVpc") {
        Some(event) => {
            let event_time = NaiveDateTime::from_timestamp(event.event_time.as_ref().unwrap().round() as i64, 0);
            let username = event.username.as_ref().unwrap();
            println!("region {:?} vpc_id {:?} created on {:?} by user {:?}", region, vpc_id, event_time, username);
        },
        None => {
            println!("region {:?} vpc_id {:?} Unknown creation time", region, vpc_id);
        }
    };
}


fn describe_events(region: Region, vpc_id: String) -> impl Future<Item=(), Error=LookupEventsError> {
    let client = get_events_client(region.clone());
    let request = vpc_events_request(vpc_id.clone());
    let events_future = client.lookup_events(request.clone())
        .map( move |v| {
            let events = v.events.unwrap();
            handle_events(events, vpc_id, region);
        });
    events_future
}


fn describe_vpcs_future(region: Region) -> impl Future<Item=DescribeVpcsResult, Error=()>{
    debug!("calling describe vpcs in region {:?}", &region);
    let request = DescribeVpcsRequest {
        dry_run: Some(false),
        filters: None,
        vpc_ids: None,
    };
    let client = get_ec2_client(region.clone());
    let f = client.describe_vpcs(request)
        .map_err( |e|
            if let DescribeVpcsError::Unknown(http_error) = e {
                let s = str::from_utf8(&http_error.body).unwrap();
                println!("DescribeVpcsError : {:?}, {:?}", http_error.status, s);
            } else {
                println!("Other inner error {:?}", e);
            });
    return f
}

fn spawn_describe_events(region: Region , vpc_id: String) {
    let r = region.clone();
    let v = vpc_id.clone();
    let handle_error = |e: LookupEventsError| {
        if let LookupEventsError::Unknown(http_error) = e {
            let body = str::from_utf8(&http_error.body).unwrap();
            if http_error.status.as_u16() == 400 && body.contains("ThrottlingException") {
                spawn_describe_events(r, v);
            } else {
                println!("LookupEventsError::Unknown {:?}", body);
            }
        } else {
            println!("LookupEventsError {:?}", e);
        };
    };

    let f =
        describe_events(region.clone(), vpc_id).map_err(handle_error);
    tokio::spawn(f);
}

struct VpcInfo {
    vpc_id: String,
    region: Region,
    creation_time: Option<f64>,
    created_by: Option<String>,
}

struct VpcInfoStream {

}

fn all_regions() -> Result<(), ()>{
    for region in regions() {
        let f =
            describe_vpcs_future(region.clone())
                .and_then(
                    move |v | {
                        let vpcs = v.vpcs.unwrap();
                        debug!("found {} vpcs in region {:?}", vpcs.len(), region.clone());
                        for vpc in vpcs {
                            if vpc.vpc_id.is_some() {
                                spawn_describe_events(region.clone(), vpc.vpc_id.unwrap());
                            }
                        }
                        Ok(())
                    }
                );
        tokio::spawn(f);
    }
    Ok(())
}

fn _main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    info!("starting {:?}", Local::now().time().to_string());
    tokio::run(lazy(all_regions));
    info!("done {:?}", Local::now().time().to_string());
}

pub fn just_print<T, E>(f: impl Future<Item=T, Error=E>) -> impl Future<Item=(), Error=()>
    where T: fmt::Debug, E: fmt::Debug {
    f.map(|v| {println!("got a result {:?}", v);} )
        .map_err(|_e| {println!("got an err {:?}", _e);})

}


fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    info!("starting {:?}", Local::now().time().to_string());
    let region = Region::UsEast1;
    let client = get_ec2_client(region.clone());
    let x = VpcStream::all(client).collect();
    let y = just_print(x);
    tokio::run(y);
    info!("done {:?}", Local::now().time().to_string());
}