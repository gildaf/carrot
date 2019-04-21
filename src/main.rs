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
use std::collections::HashMap;
use tokio::prelude::*;
use tokio::sync::mpsc::{channel, Sender};

use rusoto_cloudtrail::{CloudTrailClient, Event};
use rusoto_core::{HttpClient, Region};
use rusoto_ec2::{Ec2Client, Vpc};

mod aws;
mod errors;
mod events_stream;
mod vpc_info;
mod vpc_stream;
use aws::{profile_provider, regions};
use errors::Failure;
use events_stream::EventStream;
use vpc_info::VpcInfo;
use vpc_stream::VpcStream;

fn get_events_client(region: Region) -> CloudTrailClient {
    CloudTrailClient::new_with(HttpClient::new().unwrap(), profile_provider(), region)
}

fn get_ec2_client(region: Region) -> Ec2Client {
    Ec2Client::new_with(HttpClient::new().unwrap(), profile_provider(), region)
}

fn load_vpc_info(region: Region, vpc_id: String) -> impl Future<Item = VpcInfo, Error = Failure> {
    let client = get_events_client(region.clone());
    let events_stream = EventStream::all_per_vpc(client, vpc_id.clone());
    let relevant_events = events_stream
        .map_err(Failure::from)
        .filter(|event| event.event_name.as_ref().unwrap().contains("CreateVpc"))
        .collect();
    info!("starting to collect streams for {:?}", &vpc_id);

    relevant_events.map(move |events: Vec<Event>| VpcInfo::from_events(vpc_id, region, events))
}

fn collect_vpcs_info(
    region: Region,
    sender: Sender<VpcInfo>,
) -> impl Future<Item = (), Error = Failure> {
    let client = get_ec2_client(region.clone());
    let vpc_to_vpc_info = move |vpc: Vpc| {
        let sender = sender.clone();
        let vpc_id = vpc.vpc_id.unwrap();
        load_vpc_info(region.clone(), vpc_id)
            .and_then(|vpc_info| {
                sender
                    .send(vpc_info)
                    .map(|result| {
                        debug!("good {:?}", result);
                    })
                    .map_err(Failure::from)
            })
            .map_err(|err: Failure| {
                error!("failure {:?}", err);
            })
    };
    VpcStream::all(client)
        .for_each(move |vpc| {
            tokio::spawn(vpc_to_vpc_info(vpc));
            Ok(())
        })
        .map_err(Failure::from)
}

fn print_info<T>(all_vpc_infos: Vec<VpcInfo>) -> Result<(), T> {
    let mut knowns: HashMap<String, Vec<VpcInfo>> = HashMap::new();
    let mut unknowns: Vec<VpcInfo> = Vec::new();
    for vpc_info in all_vpc_infos {
        match vpc_info.created_by() {
            Some(name) => {
                if let Some(vpc_infos) = knowns.get_mut(name.as_str()) {
                    vpc_infos.push(vpc_info)
                } else {
                    knowns.insert(name.clone(), vec![vpc_info]);
                }
            }
            None => {
                unknowns.push(vpc_info);
            }
        }
    }
    println!(
        "knowns length= {}, unknowns length = {}",
        &knowns.len(),
        &unknowns.len()
    );
    for (user, vpc_infos) in knowns {
        println!("user: {}", user);
        for vpc_info in vpc_infos {
            println!("\t{:?}", vpc_info);
        }
    }
    println!("############################################################");
    println!("unknowns:");
    for vpc_info in unknowns {
        println!("\t{:?}", vpc_info);
    }
    Ok(())
}

fn get_all_info() -> impl Future<Item = (), Error = ()> {
    let (sender, receiver) = channel::<VpcInfo>(100);
    regions().iter().for_each(|region| {
        let sender = sender.clone();
        let vpcs_future = collect_vpcs_info(region.clone(), sender).map_err(|e| {
            error!("{:?}", e);
        });
        tokio::spawn(vpcs_future);
    });

    receiver
        .collect()
        .and_then(print_info)
        .map_err(|e| error!("receiver failed!! {:?}", e))
}

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));
    warn!("starting");
    tokio::run(lazy(get_all_info));
    warn!("done");
}
