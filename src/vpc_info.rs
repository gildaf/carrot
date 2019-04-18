use chrono::prelude::*;
use rusoto_cloudtrail::Event;
use rusoto_core::Region;
use std::fmt;

type VpcID = String;

pub struct VpcInfo {
    vpc_id: VpcID,
    region: Region,
    creation_time: Option<f64>,
    created_by: Option<String>,
}

impl VpcInfo {
    fn new(vpc_id: VpcID, region: Region) -> VpcInfo {
        VpcInfo {
            vpc_id,
            region,
            creation_time: None,
            created_by: None,
        }
    }

    pub fn from_events(vpc_id: VpcID, region: Region, events: Vec<Event>) -> VpcInfo {
        let mut vpc_info = Self::new(vpc_id, region);
        for event in events {
            let Event {
                event_name,
                username,
                event_time,
                ..
            } = event;
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
            &Some(time) => NaiveDateTime::from_timestamp(time.round() as i64, 0).to_string(),
            None => "Unknown".to_string(),
        };
        let created_by = match &self.created_by {
            &Some(ref username) => username.as_str(),
            None => "Unknown",
        };

        write!(
            f,
            "vpc: {} ({:?}), created by {} on {}",
            self.vpc_id.as_str(),
            self.region,
            created_by,
            creation_time
        )
    }
}
