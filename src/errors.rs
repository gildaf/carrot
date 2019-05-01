use rusoto_cloudtrail::LookupEventsError;
use rusoto_ec2::DescribeVpcsError;
use std::str;
use tokio::sync::mpsc::error::SendError;

#[derive(Debug)]
pub enum CarrotError {
    DescribeVpcsFailed(String),
    LookUpEventsFailed(String),
    SendingVpcInfoFailed(String),
}

impl From<LookupEventsError> for CarrotError {
    fn from(e: LookupEventsError) -> Self {
        if let LookupEventsError::Unknown(http_error) = e {
            let s = str::from_utf8(&http_error.body).unwrap();
            error!("LookupEventsError : {:?}, {:?}", &http_error.status, s);
            CarrotError::LookUpEventsFailed(s.to_string())
        } else {
            let msg = format!("{:?}", e);
            CarrotError::LookUpEventsFailed(msg)
        }
    }
}

impl From<DescribeVpcsError> for CarrotError {
    fn from(e: DescribeVpcsError) -> Self {
        if let DescribeVpcsError::Unknown(http_error) = e {
            let s = str::from_utf8(&http_error.body).unwrap();
            error!("DescribeVpcsError: {:?}, {:?}", &http_error.status, s);
            CarrotError::DescribeVpcsFailed(s.to_string())
        } else {
            let msg = format!("{:?}", e);
            CarrotError::DescribeVpcsFailed(msg)
        }
    }
}

impl From<SendError> for CarrotError {
    fn from(e: SendError) -> Self {
        let msg = format!("{:?}", e);
        CarrotError::SendingVpcInfoFailed(msg)
    }
}
