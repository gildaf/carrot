use std::string::String;
use futures::prelude::*;
//use tokio::timer::Interval;
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


pub struct GetEventsStream {
    client: CloudTrailClient,
    request: LookupEventsRequest,
    _future: RusotoFuture<LookupEventsResponse, LookupEventsError>,
    _token: Option<String>,
    _events_stream: Option<Box<futures::stream::Stream<Item=Event, Error=LookupEventsError> + Send>>

//    next_reques:
}

fn vpc_events_request(vpc_id: String) -> LookupEventsRequest {
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
        next_token: None,
        start_time: None,
    };
    request
}
impl GetEventsStream {
    pub fn new(client: CloudTrailClient, request: LookupEventsRequest) ->  GetEventsStream {
        let _future = client.lookup_events(request.clone());
        GetEventsStream { client, request, _future , _events_stream: None, _token: None}
    }

    pub fn new_for_vpc(client: CloudTrailClient, vpc_id: String) ->  GetEventsStream {
        GetEventsStream::new(client, vpc_events_request(vpc_id))
    }

    pub fn get_vpc_id(&self) -> Option<String> {
        if let Some(ref attrs) = &self.request.lookup_attributes {
            Some(attrs[0].attribute_value.clone())
        } else {
            None
        }
    }
}

impl Stream for GetEventsStream {
    type Item = Event;
    type Error = LookupEventsError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        //        Poll<Option<Self::Item>, Self::Error>
        //        Result<Async<T>, E>;
        //        Result<Async<Option<Self::Item>>, Self::Error>;
        if let Some(ref mut s) = &mut self._events_stream {
            match try_ready!(s.poll()) {
                Some(val) => {
                    Ok(Async::Ready(Some(val)))
                },
                None => {
                    // no more events
                    self._events_stream = None;
                    match self._token.take() {
                        Some(token) => {
                            self.request.next_token = Some(token);
                            println!("looking for events for vpc {:?}", self.get_vpc_id());
                            self._future = self.client.lookup_events(self.request.clone());
                            Ok(Async::NotReady)
                        }
                        None => {
                            // we are done
                            Ok(Async::Ready(None))
                        }
                    }
                }
            }
        } else {
//            println!("waiting for EventsLookupResult for vpc {:?}", self.get_vpc_id());
            let result: LookupEventsResponse  = try_ready!(self._future.poll());
            self._token = result.next_token;
            self._events_stream = Some(Box::new(futures::stream::iter_ok(result.events.unwrap())));
            Ok(Async::NotReady)
        }
    }
}
//        match selfAsync::Ready()


/*
pub struct GetEvents {
    stream: GetEventsStream,
    interval: Interval

}

impl GetEvents {
    pub fn new(client: CloudTrailClient, request: LookupEventsRequest) ->  GetEvents {
        GetEvents {
            stream: GetEventsStream::new(client, request),
            interval: Interval::new_interval(Duration::from_millis(500))
        }
    }
}

impl Future for GetEvents {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        //        match self.stream.poll() {
//        Poll<T, E>
//        Poll<T, E> = Result<Async<T>, E>;
        loop {
            println!("calling");
            match self.stream.poll() {
                Ok(Async::Ready(None)) => {
                    return Ok(Async::Ready(()))
                },
                Ok(Async::Ready(Some(result))) => {
                    println!("got result");
                    for event in result.events.unwrap(){
                        println!("event {:?}", event);
                    }
                },
                Ok(Async::NotReady) => {
                    println!("Not Ready yet!");
                    return Ok(Async::NotReady)
                },
                Err(error) =>{
                    println!("error in request {:?}", error);
                    match error {
                        LookupEventsError::Unknown(http_error) => {
                            let s = str::from_utf8(&http_error.body).unwrap();
                            println!("status: {:?}, {:?}", http_error.status, s);
                        }
                        _ => {
                            println!("error {:?}", error);
                        }
                    }
                    return Err(())
                }
            }
        }
    }
}

pub fn simple_events(client: CloudTrailClient, request: LookupEventsRequest) {
    let mut _future = client.lookup_events(request.clone());
//    RusotoFuture<LookupEventsResponse, LookupEventsError>
//    GetEvents { client, request, _future: Some(_future) }
    loop {
        match _future.poll() {
//        Poll<T, E>
//        Poll<T, E> = Result<Async<T>, E>;
            Ok(Async::Ready(result)) => {
                println!("polling2!!");
//            let next_toke = result.next_token.clone();
//            if next_toke.is_some() {
//                let mut request = self.request.clone();
//                request.next_token = next_toke;
//                self._future = Some(self.client.lookup_events(request));
//            }
                for event in result.events.unwrap(){
                    println!("event {:?}", event)
                }

            }
            Ok(Async::NotReady) => {
                println!("not ready");
//                Ok(Async::NotReady);
            }
            Err(e) => {
                println!("error");
//                println!()
            }
        }
    }

}
//        match selfAsync::Ready()



fn get_events(client: &CloudTrail, vpc_id: &str, token: Option<String>)
              -> RusotoFuture<LookupEventsResponse, LookupEventsError> {
//    pub struct LookupEventsRequest {
//        pub end_time: Option<f64>,
//        pub lookup_attributes: Option<Vec<LookupAttribute>>,
//        pub max_results: Option<i64>,
//        pub next_token: Option<String>,
//        pub start_time: Option<f64>,
//    }
    let attrs = vec![
        LookupAttribute{
            attribute_key: "ResourceName".to_string(),
            attribute_value: vpc_id.to_string(),
        }
    ];
    let request = LookupEventsRequest {
        end_time: None,
        lookup_attributes: Some(attrs),
        max_results: None,
        next_token: token,
        start_time: None,
    };

    client.lookup_events(request)
}
*/
