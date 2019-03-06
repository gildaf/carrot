extern crate env_logger;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_cloudtrail;

//extern crate rusoto_sts;


//use std::default::Default;

use std::str;
//use std::collections::HashSet;
use std::path::PathBuf;
use dirs::home_dir;
use rusoto_core::{Region, HttpClient, RusotoFuture};
use rusoto_core::credential::ProfileProvider;
use rusoto_ec2::{
    Ec2Client, Ec2, Vpc, Filter,
    DescribeVpcsRequest, DescribeVpcsResult, DescribeVpcsError,
    DescribeInstancesRequest, DescribeInstancesResult, DescribeInstancesError,
};
use rusoto_cloudtrail::{
    CloudTrail, CloudTrailClient,
    LookupEventsRequest, LookupEventsResponse, LookupEventsError,
    LookupAttribute, Event
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

fn get_events(client: &CloudTrail, vpc_id: &str, token: Option<String>)
              -> RusotoFuture<LookupEventsResponse, LookupEventsError> {
//    pub struct LookupEventsRequest {
//        pub end_time: Option<f64>,
//        pub lookup_attributes: Option<Vec<LookupAttribute>>,
//        pub max_results: Option<i64>,
//        pub next_token: Option<String>,
//        pub start_time: Option<f64>,
//    }
    let attrs = vec![
        LookupAttribute{
            attribute_key: "ResourceName".to_string(),
            attribute_value: vpc_id.to_string(),
        }
    ];
    let request = LookupEventsRequest {
        end_time: None,
        lookup_attributes: Some(attrs),
        max_results: None,
        next_token: token,
        start_time: None,
    };

    client.lookup_events(request)
}

struct VpcInfo {
    vpc: Vpc,
    created: Option<Event>,
    deleted: Option<Event>,
}

fn handle_events_future(vpc_id: &str, result: LookupEventsResponse) {
    println!("vpc id {:?}", vpc_id);
    fn print_event(event: Event) -> Event{
        println!("\tevent name{:?}", event.event_name.as_ref().unwrap());
        println!("the event {:?}", event.cloud_trail_event.as_ref().unwrap());
        println!("\tuser name {:?}", event.username.as_ref().unwrap());
        event
    }

//    let mut names: HashSet<String> = HashSet::new();
    result.events.unwrap().into_iter()
        .filter(|event| event.event_name.as_ref().unwrap().to_lowercase().contains("vpc"))
        .map(print_event );
}


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

/*
fn _print_vpcs(provider: ProfileProvider, region: Region) {
//    let region_name = region.name();
    match get_vpcs(provider.clone(), region.clone()).sync() {
        Ok(result) => {
            let vpcs = result.vpcs.unwrap();
//            let  a = vec![1,2];
//            a.len()
            println!("found  {:?} vpcs ", vpcs.len());
            let region_name = region.name();
            for vpc in &vpcs {
                println!("region {}, vpc_id {:?}", region_name, vpc.vpc_id);
                get_instances(vpc, provider.clone(), region.clone()).sync();
//                println!("tags {:?}", vpc.tags);
            }

        }
        Err(error) => {
//            let a: () = error;
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

fn main() {
    let _ = env_logger::try_init();
    let provider = ProfileProvider::with_configuration(aws_creds_location().unwrap(),"pcf-qa");
    for region in regions() {
        let vpc_id = "vpc-0cf966f1ef951882d";
        if region != &Region::UsEast1 {
            continue
        }
        let mut token = None;
        let client = CloudTrailClient::new_with(HttpClient::new().unwrap(), provider.clone(), region.clone());
        loop {
            let f_events = get_events(&client, vpc_id, token.clone()).sync();
            match f_events {
                Ok(result) => {
        //          LookupEventsResponse, LookupEventsError
                    let next_token = result.next_token.clone();
                    handle_events_future(vpc_id, result);
                    if next_token.is_none() {
                        break
                    } else {
                        token = next_token;
                    }
                },
                Err(error) => {
                    println!("error in region {} {:?}", region.name(), error);
                    match error {
                        LookupEventsError::Unknown(http_error) => {
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

    }

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