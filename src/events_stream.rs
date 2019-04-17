use futures::prelude::*;
use rusoto_cloudtrail::{
    CloudTrail, CloudTrailClient, Event, LookupAttribute, LookupEventsError, LookupEventsRequest,
    LookupEventsResponse,
};
use rusoto_core::RusotoFuture;
use std::string::String;
use std::time::{Duration, Instant};

use serde_json::from_slice;
use serde_json::Value as SerdeJsonValue;
use tokio::timer::Delay;

pub struct EventStream {
    client: CloudTrailClient,
    state: Option<EventStreamState>,
    vpc_id: String,
}

enum EventStreamState {
    EventStreamWaitResult {
        request: LookupEventsRequest,
        future: RusotoFuture<LookupEventsResponse, LookupEventsError>,
    },
    EventStreamThrottled {
        request: LookupEventsRequest,
        delay: Delay,
    },
    EventStreamResult {
        request: LookupEventsRequest,
        next_token: Option<String>,
        my_stream: Box<futures::stream::Stream<Item = Event, Error = LookupEventsError> + Send>,
    },
}

fn _vpc_events_request(vpc_id: String, token: Option<String>) -> LookupEventsRequest {
    let attrs = vec![LookupAttribute {
        attribute_key: "ResourceName".to_string(),
        attribute_value: vpc_id,
    }];
    let request = LookupEventsRequest {
        end_time: None,
        lookup_attributes: Some(attrs),
        max_results: None,
        next_token: token,
        start_time: None,
    };
    request
}

impl EventStream {
    pub fn all_per_vpc(client: CloudTrailClient, vpc_id: String) -> EventStream {
        let request = _vpc_events_request(vpc_id.clone(), None);
        let future = client.lookup_events(request.clone());
        EventStream {
            client,
            state: Some(EventStreamState::EventStreamWaitResult { request, future }),
            vpc_id,
        }
    }
}

impl Stream for EventStream {
    type Item = Event;
    type Error = LookupEventsError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self
            .state
            .take()
            .expect("Stream called twice after exhaustion")
        {
            EventStreamState::EventStreamWaitResult {
                request,
                mut future,
            } => match future.poll() {
                Ok(Async::Ready(result)) => {
                    let next_token = result.next_token.clone();
                    let my_stream = Box::new(futures::stream::iter_ok(result.events.unwrap()));
                    self.state = Some(EventStreamState::EventStreamResult {
                        request,
                        next_token,
                        my_stream,
                    });
                    self.poll()
                }
                Ok(Async::NotReady) => {
                    debug!("{}: not ready ", self.vpc_id.as_str());
                    self.state = Some(EventStreamState::EventStreamWaitResult { request, future });
                    Ok(Async::NotReady)
                }
                Err(e) => {
                    let vpc_id = self.vpc_id.as_str();
                    if e.is_throttle() {
                        info!("{}: Got throttled on lookup_events", vpc_id);
                        let when = Instant::now() + Duration::from_millis(100);
                        self.state = Some(EventStreamState::EventStreamThrottled {
                            request,
                            delay: Delay::new(when),
                        });
                        self.poll()
                    } else {
                        error!("{}: error in lookup events", vpc_id);
                        Err(e)
                    }
                }
            },
            EventStreamState::EventStreamResult {
                mut request,
                next_token,
                mut my_stream,
            } => {
                match my_stream.poll() {
                    Ok(Async::Ready(Some(event))) => {
                        self.state = Some(EventStreamState::EventStreamResult {
                            request,
                            next_token,
                            my_stream,
                        });
                        Ok(Async::Ready(Some(event)))
                    }
                    Ok(Async::Ready(None)) => match next_token {
                        Some(token) => {
                            request.next_token = Some(token);
                            let future = self.client.lookup_events(request.clone());
                            self.state =
                                Some(EventStreamState::EventStreamWaitResult { request, future });
                            self.poll()
                        }
                        None => {
                            self.state = Some(EventStreamState::EventStreamResult {
                                request,
                                next_token,
                                my_stream,
                            });
                            Ok(Async::Ready(None))
                        }
                    },
                    Ok(Async::NotReady) => {
                        // this should never happen
                        panic!("this should never happen")
                    }
                    Err(e) => Err(e),
                }
            }
            EventStreamState::EventStreamThrottled { request, mut delay } => {
                debug!("{}: checking throttling", self.vpc_id.as_str());
                match delay.poll() {
                    Ok(Async::Ready(_)) => {
                        debug!(
                            "{}: delay is ready. calling lookup_events again",
                            self.vpc_id.as_str()
                        );
                        let future = self.client.lookup_events(request.clone());
                        self.state =
                            Some(EventStreamState::EventStreamWaitResult { request, future });
                        self.poll()
                    }
                    Ok(Async::NotReady) => {
                        debug!("{}: delay is not ready yet", self.vpc_id.as_str());
                        self.state =
                            Some(EventStreamState::EventStreamThrottled { request, delay });
                        Ok(Async::NotReady)
                    }
                    Err(_) => {
                        // The delay can fail if the Tokio runtime is unavailable.
                        // for now, the error is ignored.
                        panic!("delay failed");
                    }
                }
            }
        }
    }
}

pub trait IsThrottle {
    fn is_throttle(&self) -> bool;
}

impl IsThrottle for LookupEventsError {
    fn is_throttle(&self) -> bool {
        match self {
            LookupEventsError::Unknown(http_error) => {
                let json = from_slice::<SerdeJsonValue>(&http_error.body).unwrap();
                let err_type = json
                    .get("__type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown");
                return err_type == "ThrottlingException";
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use rusoto_mock::{MockCredentialsProvider, MockRequestDispatcher};

    #[test]
    fn test_event_stream_simple() {
        let client = CloudTrailClient::new_with(
            MockRequestDispatcher::with_status(200),
            MockCredentialsProvider,
            Default::default(),
        );

        let stream = EventStream::all_per_vpc(client, "vpc-1234".to_string());
        assert_eq!(stream.vpc_id.as_str(), "vpc-1234");
    }
}
