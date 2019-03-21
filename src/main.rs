extern crate env_logger;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_cloudtrail;

#[macro_use]
extern crate futures;
extern crate tokio;
extern crate chrono;
//extern crate rusoto_sts;


//use std::default::Default;
use tokio::prelude::*;
use chrono::prelude::*;
use std::time::{Duration,};
use std::{str};
//use std::error::Error;
//use std::collections::HashSet;
use std::path::PathBuf;
use futures::lazy;

use dirs::home_dir;
use rusoto_core::{Region, HttpClient, RusotoFuture};
use rusoto_core::credential::ProfileProvider;
use rusoto_ec2::{
    Ec2Client, Ec2,
//    Filter,
    Vpc,
    DescribeVpcsRequest, DescribeVpcsResult, DescribeVpcsError,
//    DescribeInstancesRequest, DescribeInstancesResult, DescribeInstancesError,
};
use rusoto_cloudtrail::{
    CloudTrailClient,
    CloudTrail,
    LookupEventsRequest,
    LookupEventsResponse,
    LookupEventsError,
    LookupAttribute,
    Event
};

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


fn aws_creds_location() -> Result<PathBuf, &'static str> {
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

/*
fn get_all_events(vpc_id: &str, mut getter: GetEvents) {
    loop {
        match getter.poll() {
            Ok(Async::Ready(Some(result))) => {
                handle_events_future(vpc_id, result);
            }
            Ok(Async::Ready(None)) => {
                break
            }
            Ok(Async::NotReady) => {
                sleep_now()
            }
            Err(error) => {
                println!("error in request {:?}", error);
                match error {
                    LookupEventsError::Unknown(http_error) => {
                        let s = str::from_utf8(&http_error.body).unwrap();
                        println!("status: {:?}, {:?}", http_error.status, s);
                    }
                    _ => {
                        println!("error {:?}", error);
                    }
                }
                break
            }
        }
    }
}
*/


fn get_vpcs(provider: ProfileProvider, region: Region) -> RusotoFuture<DescribeVpcsResult, DescribeVpcsError>{
    let client = Ec2Client::new_with(HttpClient::new().unwrap(), provider, region.clone());
    let request = DescribeVpcsRequest {
        dry_run: Some(false),
        filters: None,
        vpc_ids: None,
//        vpc_ids: Some(vec!["vpc-0d71cf41493261272".to_string()]),
    };
    client.describe_vpcs(request)
}

/*
fn get_instances(vpc: &Vpc, provider: ProfileProvider, region: Region, token: Option<String>) -> RusotoFuture<DescribeInstancesResult, DescribeInstancesError>{
    let client = Ec2Client::new_with(HttpClient::new().unwrap(), provider, region.clone());
    let vpc_id =  vpc.vpc_id.clone().unwrap();
    let vpc_filter = Filter {
        name: Some("vpc-id".to_string()),
        values: Some(vec![vpc_id]),
    };

    let request = DescribeInstancesRequest {
        /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
        dry_run: Some(false),
        filters: Some(vec![vpc_filter]),
        instance_ids: None,
        max_results: None,
        next_token: token,
    };

    let f = client.describe_instances(request);
}
*/

fn sleep_now() {
    println!("sleeping for a second");
    for _ in 1..10000 {

    }


//    thread::sleep(time::Duration::from_secs(1));
    println!("im up");
}


fn profile_provider() -> ProfileProvider {
    ProfileProvider::with_configuration(aws_creds_location().unwrap(), "pcf-qa")
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


fn print_vpcs(f: impl Future) {

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

fn describe_events(region: Region, vpc_id: String) -> impl Future<Item=(), Error=LookupEventsError> {
    let client = get_events_client(region.clone());
    let request = vpc_events_request(vpc_id);
    let events_future = client.lookup_events(request.clone())
        .map( |v| {
            let region = region;
            let events = v.events.unwrap();
            for event in events {
                if let Some(event_name) = event.event_name.clone() {
                    if event_name == "CreateVpc".to_string() {
                        println!("region {:?} event {:?}", &region, event);
                    }
                }

            }
        });
    events_future

}
/*
fn all_events_future(region: Region) -> impl FnOnce(DescribeVpcsResult) -> Result<(),()>{
    let _all_events = move |v : DescribeVpcsResult| {
        println!("found {} vpcs in region {:?}", &v.vpcs.unwrap().len(), region.clone());
        for vpc in v.vpcs.unwrap() {
            if vpc.vpc_id.is_some() {
                let f = describe_events(region.clone(), vpc.vpc_id.unwrap());
                tokio::spawn(f);
            }
        }
        Ok(())
    };
    _all_events
}
*/

fn describe_vpcs_future(region: Region) -> impl Future<Item=DescribeVpcsResult, Error=()>{
    println!("region {:?}", &region);
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

fn all_regions() -> Result<(), ()>{
    for region in regions() {
        let f =
            describe_vpcs_future(region.clone())
                .and_then(
                    move |v | {
                        let vpcs = v.vpcs.unwrap();
                        println!("found {} vpcs in region {:?}", vpcs.len(), region.clone());
                        for vpc in vpcs {
                            if vpc.vpc_id.is_some() {
                                let f = describe_events(region.clone(), vpc.vpc_id.unwrap())
                                    .map_err( |e|
                                        if let LookupEventsError::Unknown(http_error) = e {
                                            let s = str::from_utf8(&http_error.body).unwrap();
                                            println!("LookupEventsError : {:?}, {:?}", http_error.status, s);
                                        } else {
                                            println!("Other inner error {:?}", e);
                                        }
                                    );
                                tokio::spawn(f);
                            }
                        }
                        Ok(())
                    }
                );
//            .map_err( |e|  println!("error 123 {:?}", e));
        tokio::spawn(f);
    }
    Ok(())
}
fn main() {
    let _ = env_logger::try_init();

    println!("starting {:?}", Local::now().time().to_string());
    tokio::run(lazy(all_regions));
    println!("done {:?}", Local::now().time().to_string());


    /*
    for region in regions() {
    //        let region_name = region.clone().name();
        let f_vpcs = get_vpcs(provider.clone(), region.clone()).sync();
        match f_vpcs {
            Ok(result) => {
                let vpcs = result.vpcs.unwrap();
                println!("found  {:?} vpcs ", vpcs.len());
                let region_name = region.name();
                for vpc in &vpcs {
                    let vpc_id = &vpc.vpc_id;
                    println!("region {}, vpc_id {:?}", region_name, vpc_id);
                    loop {
                        let f_instances = get_instances(vpc, provider.clone(), region.clone(), None).sync();
                        //                println!("tags {:?}", vpc.tags);
                        match f_instances {
                            Ok(instances_result) => {
                                let reservations = instances_result.reservations.unwrap();
                                for reservation in reservations {
                                    for instance in reservation.instances.unwrap() {
                                        println!("vcp id {:?} instance id {:?}", vpc_id, instance.instance_id.unwrap());
                                    }
                                }
                                if instances_result.next_token.is_none() {
                                    break
                                }
                            },
                            Err(error) => {
                                println!("failed to get instances from vpc {:?} region {}", vpc_id, region_name);
                                match error {
                                    DescribeInstancesError::Unknown(http_error) => {
                                        let s = str::from_utf8(&http_error.body).unwrap();
                                        println!("status: {:?}, {:?}", http_error.status, s);
                                    }
                                    _ => {
                                        println!("error {:?}", error);
                                    }
                                }
                                break
                            }
                        }
                    }

                }
            },
            Err(error) => {
                println!("error in region {} {:?}", region.name(), error);
                match error {
                    DescribeVpcsError::Unknown(http_error) => {
                        let s = str::from_utf8(&http_error.body).unwrap();
                        println!("status: {:?}, {:?}", http_error.status, s);
                    }
                    _ => {
                        println!("error {:?}", error);
                    }
                }

            }
        }
    }
    */
}
