use std::{str, time::Duration};

use futures::prelude::*;
use tokio::timer::Interval;
use rusoto_core::{
//    Region, HttpClient,
RusotoFuture};
use rusoto_cloudtrail::{
    CloudTrail, CloudTrailClient,
    LookupEventsRequest, LookupEventsResponse, LookupEventsError,
//    LookupAttribute, Event
};


pub struct GetEventsStream {
    client: CloudTrailClient,
    request: LookupEventsRequest,
    _future: Option<RusotoFuture<LookupEventsResponse, LookupEventsError>>,
//    next_reques:
}

impl GetEventsStream {
    pub fn new(client: CloudTrailClient, request: LookupEventsRequest) ->  GetEventsStream {
        let _future = client.lookup_events(request.clone());
        GetEventsStream { client, request, _future: Some(_future) }
    }
}


impl Stream for GetEventsStream {
    type Item = LookupEventsResponse;
    type Error = LookupEventsError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        //        Poll<Option<Self::Item>, Self::Error>
        //        Result<Async<T>, E>;
        //        Result<Async<Option<Self::Item>>, Self::Error>;

        match self._future.take() {
            Some(mut f) => {
                println!("polling!!");
                match f.poll() {
                    Ok(Async::Ready(result)) => {
                        println!("polling2!!");
                        let next_toke = result.next_token.clone();
                        if next_toke.is_some() {
                            let mut request = self.request.clone();
                            request.next_token = next_toke;
                            self._future = Some(self.client.lookup_events(request));
                        }
                        Ok(Async::Ready(Some(result)))
                    }
                    Ok(Async::NotReady) => {
                        println!("polling4!!");
                        self._future = Some(f);
                        Ok(Async::NotReady)
                    }
                    Err(e) => {
                        println!("polling5!!");
                        Err(e)
                    }
                }
            }
            None => {
                println!("NONE!!!");
                Ok(Async::Ready(None))
            }
        }
//        match selfAsync::Ready()
    }
}

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


/*
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
