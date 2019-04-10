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

enum Token {
    StartToken,
    TokenFromResponse(Option<String>),
}

pub struct EventStream {
    state: Option<EventStreamState>,
}

enum EventStreamState {
    EventStreamWait {
        client: CloudTrailClient,
        request: LookupEventsRequest,
        future: RusotoFuture<LookupEventsResponse, LookupEventsError>,
    },
    EventStreamResult {
        client: CloudTrailClient,
        request: LookupEventsRequest,
        token: Option<String>,
        event_stream: Box<futures::stream::Stream<Item=Event, Error=LookupEventsError> + Send>
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
        let request = _vpc_events_request(vpc_id, None);
        let future = client.lookup_events(request.clone());
        EventStream {
            state: Some(EventStreamState::EventStreamWait{ client, request, future })
        }
    }
}

impl Stream for EventStream {
    type Item = Event;
    type Error = LookupEventsError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.state.take().expect("Stream called twice after exhaustion") {
            EventStreamState::EventStreamWait { client, request, mut future } => {
                match future.poll() {
                    Ok(Async::Ready(result)) => {
//                        let  LookupEventsResponse { events, next_token } = result;
                        let token = result.next_token.clone();
                        let event_stream = Box::new(futures::stream::iter_ok(result.events.unwrap()));
                        self.state = Some(EventStreamState::EventStreamResult { client, request, token, event_stream });
                        self.poll()
                    },
                    Ok(Async::NotReady) => {
                        self.state = Some(EventStreamState::EventStreamWait{ client, request, future });
                        Ok(Async::NotReady)
                    },
                    Err(e) => {
                        Err(From::from(e))
                    },
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
                                self.state = Some(EventStreamState::EventStreamWait { client, request, future });
                                self.poll()
                            },
                            None => {
                                self.state = Some(EventStreamState::EventStreamResult { client, request, token, event_stream});
                                Ok(Async::Ready(None))
                            }
                        }
                    },
                    Ok(Async::NotReady) => {
                        self.state = None;
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
