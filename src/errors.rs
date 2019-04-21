use std::str;
use rusoto_cloudtrail::LookupEventsError;
use rusoto_ec2::DescribeVpcsError;
use tokio::sync::mpsc::error::SendError;

#[derive(Debug)]
pub enum Failure {
    DescribeVpcsFailed(String),
    LookUpEventsFailed(String),
    SendingVpcInfoFailed(String),
}

impl From<LookupEventsError> for Failure {
    fn from(e: LookupEventsError) -> Self {
        if let LookupEventsError::Unknown(http_error) = e {
            let s = str::from_utf8(&http_error.body).unwrap();
            error!("LookupEventsError : {:?}, {:?}", &http_error.status, s);
            Failure::LookUpEventsFailed(s.to_string())
        } else {
            let msg = format!("{:?}", e);
            Failure::LookUpEventsFailed(msg)
        }
    }
}

impl From<DescribeVpcsError> for Failure {
    fn from(e: DescribeVpcsError) -> Self {
        if let DescribeVpcsError::Unknown(http_error) = e {
            let s = str::from_utf8(&http_error.body).unwrap();
            error!("DescribeVpcsError: {:?}, {:?}", &http_error.status, s);
            Failure::DescribeVpcsFailed(s.to_string())
        } else {
            let msg = format!("{:?}", e);
            Failure::DescribeVpcsFailed(msg)
        }
    }
}

impl From<SendError> for Failure {
    fn from(e: SendError) -> Self {
        let msg = format!("{:?}", e);
        Failure::SendingVpcInfoFailed(msg)
    }
}
