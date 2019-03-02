extern crate env_logger;
extern crate rusoto_core;
extern crate rusoto_ec2;

//extern crate rusoto_sts;


//use std::default::Default;

use std::str;
//use std::string::String;
use std::path::PathBuf;
use dirs::home_dir;
use rusoto_core::{Region, HttpClient};
use rusoto_core::credential::ProfileProvider;
use rusoto_ec2::{Ec2Client, Ec2, DescribeVpcsRequest, DescribeVpcsError};
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

fn get_vpcs(provider: ProfileProvider, region: Region) {
    let client = Ec2Client::new_with(HttpClient::new().unwrap(), provider, region.clone());
    let request = DescribeVpcsRequest {
        dry_run: Some(false),
        filters: None,
        vpc_ids: None,
//        vpc_ids: Some(vec!["vpc-0d71cf41493261272".to_string()]),
    };

    match client.describe_vpcs(request).sync() {
        Ok(result) => {
            let vpcs = result.vpcs.unwrap();
//            let  a = vec![1,2];
//            a.len()
            println!("found  {:?} vpcs ", vpcs.len());
            for vpc in &vpcs {
                println!("region {}, vpc_id {:?}", region.name(), vpc.vpc_id);
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


fn main() {
    let _ = env_logger::try_init();
    let provider = ProfileProvider::with_configuration(aws_creds_location().unwrap(),"pcf-qa");

    for region in regions() {
        get_vpcs(provider.clone(), region.clone())
    }

}