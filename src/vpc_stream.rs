use futures::prelude::*;
use futures::stream::iter_ok;
use rusoto_core::RusotoFuture;
use rusoto_ec2::{DescribeVpcsError, DescribeVpcsRequest, DescribeVpcsResult, Ec2, Ec2Client, Vpc};

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
        vpc_stream: Box<futures::stream::Stream<Item = Vpc, Error = DescribeVpcsError> + Send>,
    },
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
            state: Some(VpcStreamState::VpcStreamWait {
                client,
                request,
                future,
            }),
        }
    }
}

impl Stream for VpcStream {
    type Item = Vpc;
    type Error = DescribeVpcsError;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        match self.state.take().unwrap() {
            VpcStreamState::VpcStreamWait {
                client,
                request,
                mut future,
            } => match future.poll() {
                Ok(Async::Ready(result)) => {
                    let vpc_stream = Box::new(iter_ok(result.vpcs.unwrap()));
                    self.state = Some(VpcStreamState::VpcStreamResult {
                        client,
                        request,
                        vpc_stream,
                    });
                    self.poll()
                }
                Ok(Async::NotReady) => {
                    self.state = Some(VpcStreamState::VpcStreamWait {
                        client,
                        request,
                        future,
                    });
                    Ok(Async::NotReady)
                }
                Err(e) => Err(From::from(e)),
            },
            VpcStreamState::VpcStreamResult {
                client,
                request,
                mut vpc_stream,
            } => match vpc_stream.poll() {
                Ok(Async::Ready(Some(result))) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {
                        client,
                        request,
                        vpc_stream,
                    });
                    debug!("VpcStream: {:?}", &result.vpc_id);
                    Ok(Async::Ready(Some(result)))
                }
                Ok(Async::Ready(None)) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {
                        client,
                        request,
                        vpc_stream,
                    });
                    Ok(Async::Ready(None))
                }
                Ok(Async::NotReady) => {
                    self.state = Some(VpcStreamState::VpcStreamResult {
                        client,
                        request,
                        vpc_stream,
                    });
                    Ok(Async::NotReady)
                }
                Err(e) => Err(e),
            },
        }
    }
}
