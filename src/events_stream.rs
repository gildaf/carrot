use std::time::{Duration, Instant};
use std::string::String;
use futures::prelude::*;
use rusoto_core::{
//    Region, HttpClient,
RusotoFuture};
use rusoto_cloudtrail::{
    CloudTrail, CloudTrailClient,
    LookupEventsRequest, LookupEventsResponse, LookupEventsError,
    LookupAttribute,
    Event
};

use tokio::timer::Delay;
use serde_json::from_slice;
use serde_json::Value as SerdeJsonValue;

enum Token {
    StartToken,
    TokenFromResponse(Option<String>),
}

pub struct EventStream {
    state: Option<EventStreamState>,
    vpc_id: String,
}


enum EventStreamState {
    EventStreamWaitResult {
        client: CloudTrailClient,
        request: LookupEventsRequest,
        future: RusotoFuture<LookupEventsResponse, LookupEventsError>,
    },
    EventStreamThrottled {
        client: CloudTrailClient,
        request: LookupEventsRequest,
        delay: Delay,
    },
    EventStreamResult {
        client: CloudTrailClient,
        request: LookupEventsRequest,
        token: Option<String>,
        event_stream: Box<futures::stream::Stream<Item=Event, Error=LookupEventsError> + Send>
    }
}

impl EventStreamState {
    fn vpc_id(&self) -> &str {
        match self {
            EventStreamState::EventStreamWaitResult { client: _, ref request, ..} => {
                request.lookup_attributes.as_ref().unwrap()[0].attribute_value.as_ref()
            },
            EventStreamState::EventStreamThrottled { client: _ , ref request, ..} => {
                request.lookup_attributes.as_ref().unwrap()[0].attribute_value.as_ref()
            },
            EventStreamState::EventStreamResult { client: _ , ref request, ..} => {
                request.lookup_attributes.as_ref().unwrap()[0].attribute_value.as_ref()
            },
        }
    }
}

fn _vpc_events_request(vpc_id: String, token: Option<String>) -> LookupEventsRequest {
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
            state: Some(EventStreamState::EventStreamWaitResult { client, request, future}),
            vpc_id,
        }
    }
}

impl Stream for EventStream {
    type Item = Event;
    type Error = LookupEventsError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.state.take().expect("Stream called twice after exhaustion") {
            EventStreamState::EventStreamWaitResult { client, request, mut future } => {
                match future.poll() {
                    Ok(Async::Ready(result)) => {
//                        let  LookupEventsResponse { events, next_token } = result;
                        let token = result.next_token.clone();
                        let event_stream = Box::new(futures::stream::iter_ok(result.events.unwrap()));
                        self.state = Some(EventStreamState::EventStreamResult { client, request, token, event_stream });
                        self.poll()
                    },
                    Ok(Async::NotReady) => {
//                        println!("not ready in  {}", self.vpc_id.as_str());
                        self.state = Some(EventStreamState::EventStreamWaitResult { client, request, future});
                        Ok(Async::NotReady)
                    },
                    Err(e) => {
//                        pub fn handle_error(e: LookupEventsError) {
//                        if let LookupEventsError::Unknown(http_error) = e {
                        let vpc_id = self.vpc_id.as_str();
                        match e {
                            LookupEventsError::Unknown(http_error) => {
                                let json = from_slice::<SerdeJsonValue>(&http_error.body).unwrap();
                                let err_type = json.get("__type").and_then(|e| e.as_str()).unwrap_or("Unknown");
                                let is_throttling = err_type.contains("ThrottlingException");
                                if is_throttling {
                                    info!("{}: Got throttled on lookup_events", vpc_id);
                                    let when = Instant::now() + Duration::from_millis(100);
                                    self.state = Some(EventStreamState::EventStreamThrottled { client, request, delay: Delay::new(when)});
                                    self.poll()
                                } else {
                                    Err(LookupEventsError::from_response(http_error))
                                }
                            },
                            _ => {
                                error!("{}: error in lookup events", vpc_id);
                                Err(From::from(e))
                            }
                        }
                    }
                }
            },
            EventStreamState::EventStreamResult{ client, mut request, token, mut event_stream} => {
                match event_stream.poll() {
                    Ok(Async::Ready(Some(event))) => {
                        self.state = Some(EventStreamState::EventStreamResult { client, request, token, event_stream});
                        Ok(Async::Ready(Some(event)))
                    },
                    Ok(Async::Ready(None)) => {
                        match token {
                            Some(token) => {
                                request.next_token = Some(token);
                                let future = client.lookup_events(request.clone());
                                self.state = Some(EventStreamState::EventStreamWaitResult { client, request, future });
                                self.poll()
                            },
                            None => {
                                self.state = Some(EventStreamState::EventStreamResult { client, request, token, event_stream});
                                Ok(Async::Ready(None))
                            }
                        }
                    },
                    Ok(Async::NotReady) => {
                        // this should never happen
                        panic!("this should never happen");
                        self.state = None;
                        Ok(Async::NotReady)
                    },
                    Err(e) => {
                        Err(From::from(e))
                    },
                }
            },
            EventStreamState::EventStreamThrottled {client, request, mut delay} => {
                debug!("{}: checking throttling", self.vpc_id.as_str());

                match delay.poll() {
                    Ok(Async::Ready(_)) => {
                        debug!("{}: delay is ready. calling lookup_events again", self.vpc_id.as_str());
                        let future = client.lookup_events(request.clone());
                        self.state = Some(EventStreamState::EventStreamWaitResult { client, request, future});
                        self.poll()
                    },
                    Ok(Async::NotReady) => {
                        debug!("{}: delay is not ready yet", self.vpc_id.as_str());
                        self.state = Some(EventStreamState::EventStreamThrottled { client, request, delay });
                        Ok(Async::NotReady)
                    },
                    Err(_) => {

                        // The delay can fail if the Tokio runtime is unavailable.
                        // for now, the error is ignored.
                        panic!("delay failed");
                        Err(LookupEventsError::ParseError("delay failed".to_string()))
                    },
                }
            },
        }
    }
}
