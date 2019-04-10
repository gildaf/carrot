use futures::stream::iter_ok;
use futures::prelude::*;
use rusoto_core::{RusotoFuture};
use rusoto_ec2::{
    Ec2Client, Ec2,
    Vpc,
    DescribeVpcsRequest, DescribeVpcsResult, DescribeVpcsError,
};
//fn get_vpcs(provider: ProfileProvider, region: Region) -> RusotoFuture<DescribeVpcsResult, DescribeVpcsError>{
//    let client = Ec2Client::new_with(HttpClient::new().unwrap(), provider, region.clone());
//    let request = DescribeVpcsRequest {
//        dry_run: Some(false),
//        filters: None,
//        vpc_ids: None,
////        vpc_ids: Some(vec!["vpc-0d71cf41493261272".to_string()]),
//    };
//    client.describe_vpcs(request)
//}

pub struct VpcStream {
    state: Option<VpcStreamState>,
}

enum VpcStreamState {
    VpcStreamWait {
        client: Ec2Client,
        request: DescribeVpcsRequest,
        future: RusotoFuture<DescribeVpcsResult, DescribeVpcsError>,
    },
    VpcStreamResult {
        client: Ec2Client,
        request: DescribeVpcsRequest,
        vpc_stream: Box<futures::stream::Stream<Item=Vpc, Error=DescribeVpcsError> + Send>
    }
}

impl VpcStream {
    pub fn all(client: Ec2Client) -> VpcStream {
        let request = DescribeVpcsRequest {
            dry_run: Some(false),
            filters: None,
            vpc_ids: None,
        };
        let future = client.describe_vpcs(request.clone());
        VpcStream {
            state: Some(VpcStreamState::VpcStreamWait { client, request, future })
        }
    }
}

impl Stream for VpcStream {
    type Item = Vpc;
    type Error = DescribeVpcsError;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        match self.state.take().unwrap() {
            VpcStreamState::VpcStreamWait { client, request, mut future } => {
                match future.poll() {
                    Ok(Async::Ready(result)) => {
                        let vpc_stream = Box::new(iter_ok(result.vpcs.unwrap()));
                        self.state = Some(VpcStreamState::VpcStreamResult {client, request, vpc_stream});
                        self.poll()
                    },
                    Ok(Async::NotReady) => {
                        self.state = Some(VpcStreamState::VpcStreamWait { client, request, future });
                        Ok(Async::NotReady)
                    },
                    Err(e) => {
                        Err(From::from(e))
                    },
                }
            },
            VpcStreamState::VpcStreamResult{ client, request, mut vpc_stream } => {
                match vpc_stream.poll() {
                Ok(Async::Ready(Some(result))) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {client, request, vpc_stream});
                    println!("reuslt= {:?}", &result.vpc_id);
                    Ok(Async::Ready(Some(result)))
                },
                Ok(Async::Ready(None)) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {client, request, vpc_stream});
                    Ok(Async::Ready(None))
                },
                Ok(Async::NotReady) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {client, request, vpc_stream});
                    Ok(Async::NotReady)
                },
                Err(e) => {
                        Err(From::from(e))
                },
            }

        }

        }
    }
}

//impl _VpcStream {
//    pub fn new_with_request(client: Ec2Client, request: DescribeVpcsRequest) -> VpcStream {
//        let f = client.describe_vpcs(request);
//        return _VpcStream {
//            client,
////            request,
//            _future: f,
//            _vpc_stream: None,
//        }
//    }
//
//    pub fn new_vpcs(client: Ec2Client, vpc_ids: Vec<String>) -> VpcStream {
//        let request = DescribeVpcsRequest {
//            dry_run: Some(false),
//            filters: None,
//            vpc_ids: Some(vpc_ids),
//        };
//        VpcStream::new_with_request(client, request)
//    }
//
//    pub fn new_vpc(client: Ec2Client, vpc_id: String) -> VpcStream {
//        VpcStream::new_vpcs(client, vec![vpc_id])
//    }
//
//    pub fn get_all(client: Ec2Client) -> VpcStream {
//        let request = DescribeVpcsRequest {
//            dry_run: Some(false),
//            filters: None,
//            vpc_ids: None,
//        };
//        VpcStream::new_with_request(client, request)
//    }
//}
//
//
//impl Stream for _VpcStream {
//    type Item = Vpc;
//    type Error = DescribeVpcsError;
//
//    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
//        if let Some(ref mut s) = &mut self._vpc_stream {
//            println!("got a stream");
//            let val = try_ready!(s.poll());
//            Ok(Async::Ready(val))
//        } else {
//            println!("polling on the future");
//            let result: DescribeVpcsResult = try_ready!(self._future.poll());
//            println!("got a result");
//            self._vpc_stream = Some(Box::new(iter_ok(result.vpcs.unwrap())));
//            return Ok(Async::NotReady)
//        }
//    }
//                vpcs: Option<Vec<Vpc>>,
//}
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
}*/