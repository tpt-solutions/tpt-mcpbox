// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! A small HTTP/1.1 server surface for the MCP transports.
//!
//! * **Routing** is by exact path, then by method. A known path with an
//!   unlisted method answers `405`; an unknown path answers `404`.
//! * **Handlers** are async functions taking [`State`] and a [`Request`], and
//!   returning anything that implements [`IntoResponse`].
//! * **Bodies** are read with [`to_bytes`], which enforces a limit. The
//!   handler decides the limit, as the transports always have.
//! * **Responses** are status codes, `(status, body)` pairs, [`Json`], and
//!   [`Sse`] event streams with keep-alive comments.
//! * **Serving** is [`serve`], which returns a future with optional graceful
//!   shutdown.
//!
//! The types are built on `hyper` 1 and `tower` 0.5. Nothing here is a general
//! web framework: there are no extractors beyond [`State`], no middleware, and
//! no WebSocket or multipart support.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::{Future, IntoFuture};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use http::{HeaderName, HeaderValue, Method, StatusCode, header};
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use serde::Serialize;
use tokio::net::TcpListener;

/// A request whose body is a [`Body`].
pub type Request = http::Request<Body>;

/// A response whose body is a [`Body`].
pub type Response = http::Response<Body>;

/// A streaming body. Built from bytes, strings, a [`Stream`] of frames, or an
/// incoming request.
#[derive(Debug)]
pub struct Body(BoxBody<Bytes, io::Error>);

impl Body {
    /// An empty body.
    #[must_use]
    pub fn empty() -> Self {
        Self(Empty::new().map_err(|never| match never {}).boxed())
    }

    /// A body made of frames, for streamed responses.
    pub fn from_frame_stream<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Frame<Bytes>, io::Error>> + Send + Sync + 'static,
    {
        Self(StreamBody::new(stream).boxed())
    }

    fn from_incoming(incoming: Incoming) -> Self {
        Self(incoming.map_err(io::Error::other).boxed())
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self(Full::new(bytes).map_err(|never| match never {}).boxed())
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from(Bytes::from(bytes))
    }
}

impl From<String> for Body {
    fn from(text: String) -> Self {
        Self::from(Bytes::from(text))
    }
}

impl From<&'static str> for Body {
    fn from(text: &'static str) -> Self {
        Self::from(Bytes::from_static(text.as_bytes()))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Pin::new(&mut self.0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

/// Reads a whole body, failing if it holds more than `limit` bytes.
///
/// # Errors
///
/// Returns an error if the body is longer than `limit`, or if reading it fails.
pub async fn to_bytes(body: Body, limit: usize) -> Result<Bytes, io::Error> {
    let mut body = body;
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            if collected.len() + data.len() > limit {
                return Err(io::Error::other("body exceeds the limit"));
            }
            collected.extend_from_slice(data);
        }
    }
    Ok(Bytes::from(collected))
}

/// Something that becomes a [`Response`].
pub trait IntoResponse {
    /// Converts the value into a response.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        let mut response = http::Response::new(Body::empty());
        *response.status_mut() = self;
        response
    }
}

impl<R: IntoResponse> IntoResponse for (StatusCode, R) {
    fn into_response(self) -> Response {
        let (status, inner) = self;
        let mut response = inner.into_response();
        *response.status_mut() = status;
        response
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        http::Response::new(Body::from(self))
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        http::Response::new(Body::from(self))
    }
}

impl<const N: usize> IntoResponse for ([(HeaderName, &'static str); N], String) {
    fn into_response(self) -> Response {
        let (headers, body) = self;
        let mut response = http::Response::new(Body::from(body));
        for (name, value) in headers {
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

/// A JSON response with status 200. A value that cannot be serialized answers
/// `500`.
#[derive(Debug, Clone, Copy)]
pub struct Json<T>(pub T);

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(body) => {
                let mut response = http::Response::new(Body::from(body));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                response
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// The state a handler is given: the value passed to [`Router::with_state`].
#[derive(Debug, Clone, Copy, Default)]
pub struct State<T>(pub T);

/// One server-sent event.
#[derive(Debug, Clone, Default)]
pub struct Event {
    id: Option<String>,
    event: Option<String>,
    data: Option<String>,
}

impl Event {
    /// Sets the event id, which a client echoes back as `Last-Event-ID`.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the event name.
    #[must_use]
    pub fn event(mut self, name: impl Into<String>) -> Self {
        self.event = Some(name.into());
        self
    }

    /// Sets the data. Each line becomes a `data:` line, as the format requires.
    #[must_use]
    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// The wire encoding of the event, ending with the blank line that closes it.
    fn encode(&self) -> Bytes {
        let mut out = String::new();
        if let Some(id) = &self.id {
            out.push_str("id: ");
            out.push_str(id);
            out.push('\n');
        }
        if let Some(name) = &self.event {
            out.push_str("event: ");
            out.push_str(name);
            out.push('\n');
        }
        if let Some(data) = &self.data {
            for line in data.split('\n') {
                out.push_str("data: ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push('\n');
        Bytes::from(out)
    }
}

/// How often a comment line is sent on an idle stream, so that proxies and
/// clients do not drop it. The default is 15 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAlive {
    interval: Duration,
}

impl Default for KeepAlive {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
        }
    }
}

impl KeepAlive {
    /// Sets the interval between keep-alive comments.
    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

/// A server-sent event stream.
#[derive(Debug)]
pub struct Sse<S> {
    stream: S,
    keep_alive: Option<KeepAlive>,
}

impl<S> Sse<S> {
    /// Wraps a stream of events. Keep-alive is off until [`Sse::keep_alive`].
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            keep_alive: None,
        }
    }

    /// Sends keep-alive comments on an idle stream.
    #[must_use]
    pub fn keep_alive(mut self, keep_alive: KeepAlive) -> Self {
        self.keep_alive = Some(keep_alive);
        self
    }
}

impl<S, E> IntoResponse for Sse<S>
where
    S: Stream<Item = Result<Event, E>> + Send + Sync + 'static,
    E: StdError + Send + Sync + 'static,
{
    fn into_response(self) -> Response {
        let ticker = self.keep_alive.map(|keep_alive| {
            let mut ticker = tokio::time::interval(keep_alive.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker
        });
        let body = Body::from_frame_stream(SseFrames {
            events: Box::pin(self.stream),
            ticker,
            done: false,
        });
        let mut response = http::Response::new(body);
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        response
    }
}

/// Frames for an [`Sse`] body: events as they come, and keep-alive comments
/// while idle. Ends when the event stream ends or fails.
struct SseFrames<S> {
    events: Pin<Box<S>>,
    ticker: Option<tokio::time::Interval>,
    done: bool,
}

impl<S, E> Stream for SseFrames<S>
where
    S: Stream<Item = Result<Event, E>>,
    E: StdError,
{
    type Item = Result<Frame<Bytes>, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.events.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                return Poll::Ready(Some(Ok(Frame::data(event.encode()))));
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                self.done = true;
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }
        if let Some(ticker) = self.ticker.as_mut()
            && ticker.poll_tick(cx).is_ready()
        {
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b":\n\n")))));
        }
        Poll::Pending
    }
}

/// A handler: a function of the state and the request.
pub trait Handler<S>: Send + Sync + 'static {
    /// Runs the handler.
    fn call(&self, state: S, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send>>;
}

impl<S, F, Fut, R> Handler<S> for F
where
    S: Send + 'static,
    F: Fn(State<S>, Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoResponse + 'static,
{
    fn call(&self, state: S, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let future = self(State(state), request);
        Box::pin(async move { future.await.into_response() })
    }
}

/// The handlers for one path, by method.
pub struct MethodRouter<S> {
    handlers: Vec<(Method, Arc<dyn Handler<S>>)>,
}

impl<S> std::fmt::Debug for MethodRouter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let methods: Vec<&Method> = self.handlers.iter().map(|(method, _)| method).collect();
        f.debug_struct("MethodRouter")
            .field("methods", &methods)
            .finish()
    }
}

impl<S: Send + 'static> MethodRouter<S> {
    fn on<H: Handler<S>>(mut self, method: Method, handler: H) -> Self {
        self.handlers.push((method, Arc::new(handler)));
        self
    }

    /// Adds a `GET` handler.
    #[must_use]
    pub fn get<H: Handler<S>>(self, handler: H) -> Self {
        self.on(Method::GET, handler)
    }

    /// Adds a `POST` handler.
    #[must_use]
    pub fn post<H: Handler<S>>(self, handler: H) -> Self {
        self.on(Method::POST, handler)
    }

    /// Adds a `DELETE` handler.
    #[must_use]
    pub fn delete<H: Handler<S>>(self, handler: H) -> Self {
        self.on(Method::DELETE, handler)
    }
}

/// Method-specific routes, as `get`, `post`, and `delete` free functions. Each
/// returns a [`MethodRouter`] with one handler, which the methods above extend.
pub mod routing {
    use super::{Handler, Method, MethodRouter};
    use std::sync::Arc;

    /// A `GET` route.
    pub fn get<S: Send + 'static, H: Handler<S>>(handler: H) -> MethodRouter<S> {
        MethodRouter {
            handlers: vec![(Method::GET, Arc::new(handler))],
        }
    }

    /// A `POST` route.
    pub fn post<S: Send + 'static, H: Handler<S>>(handler: H) -> MethodRouter<S> {
        MethodRouter {
            handlers: vec![(Method::POST, Arc::new(handler))],
        }
    }

    /// A `DELETE` route.
    pub fn delete<S: Send + 'static, H: Handler<S>>(handler: H) -> MethodRouter<S> {
        MethodRouter {
            handlers: vec![(Method::DELETE, Arc::new(handler))],
        }
    }
}

pub use routing::{delete, get, post};

/// Routes being assembled. Paths are matched exactly.
pub struct Router<S = ()> {
    routes: Vec<(String, MethodRouter<S>)>,
    fallback: Option<Arc<dyn Handler<S>>>,
}

impl<S> std::fmt::Debug for Router<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<&str> = self.routes.iter().map(|(path, _)| path.as_str()).collect();
        f.debug_struct("Router").field("paths", &paths).finish()
    }
}

impl<S: Clone + Send + Sync + 'static> Default for Router<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Clone + Send + Sync + 'static> Router<S> {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: None,
        }
    }

    /// Adds the handlers for `path`.
    #[must_use]
    pub fn route(mut self, path: &str, methods: MethodRouter<S>) -> Self {
        self.routes.push((path.to_owned(), methods));
        self
    }

    /// Answers every request whose path matches no route. Without one, such
    /// requests get `404`.
    #[must_use]
    pub fn fallback<H: Handler<S>>(mut self, handler: H) -> Self {
        self.fallback = Some(Arc::new(handler));
        self
    }

    /// Fixes the state every handler receives, and returns the service.
    #[must_use]
    pub fn with_state(self, state: S) -> App {
        let routes = self
            .routes
            .into_iter()
            .map(|(path, methods)| {
                let handlers = methods
                    .handlers
                    .into_iter()
                    .map(|(method, handler)| {
                        let state = state.clone();
                        let call: Arc<dyn Fn(Request) -> ResponseFuture + Send + Sync> =
                            Arc::new(move |request| handler.call(state.clone(), request));
                        (method, call)
                    })
                    .collect();
                (path, handlers)
            })
            .collect();
        let fallback = self.fallback.map(|handler| {
            let call: RouteCall = Arc::new(move |request| handler.call(state.clone(), request));
            call
        });
        App {
            routes: Arc::new(routes),
            fallback,
            guard: None,
        }
    }
}

type ResponseFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
type RouteCall = Arc<dyn Fn(Request) -> ResponseFuture + Send + Sync>;

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<&str> = self.routes.iter().map(|(path, _)| path.as_str()).collect();
        f.debug_struct("App")
            .field("paths", &paths)
            .field("guarded", &self.guard.is_some())
            .finish()
    }
}

/// A router with its state fixed. It is a `tower` service, and [`serve`] runs
/// it on a listener.
/// Decides, before routing, whether a request may proceed: `None` lets it
/// through, `Some(response)` answers it instead.
type Guard = Arc<dyn Fn(&Request) -> Option<Response> + Send + Sync>;

/// One path and its methods, with their calls.
type Route = (String, Vec<(Method, RouteCall)>);

/// A router with its state fixed. It is a `tower` service, and [`serve`] runs
/// it on a listener.
#[derive(Clone)]
pub struct App {
    routes: Arc<Vec<Route>>,
    fallback: Option<RouteCall>,
    guard: Option<Guard>,
}

impl App {
    /// Answers one request: the matching handler, `405` for a known path with
    /// another method, or `404`.
    pub async fn respond(&self, request: Request) -> Response {
        if let Some(guard) = &self.guard
            && let Some(rejected) = guard(&request)
        {
            return rejected;
        }
        let path = request.uri().path().to_owned();
        let Some((_, handlers)) = self.routes.iter().find(|(route, _)| *route == path) else {
            return match &self.fallback {
                Some(fallback) => fallback(request).await,
                None => StatusCode::NOT_FOUND.into_response(),
            };
        };
        match handlers
            .iter()
            .find(|(method, _)| *method == request.method())
        {
            Some((_, call)) => call(request).await,
            None => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
    }
}

impl App {
    /// Runs `guard` before routing, on every request. A guard that returns a
    /// response stops the request there, including requests for unknown paths.
    #[must_use]
    pub fn guard<G>(mut self, guard: G) -> Self
    where
        G: Fn(&Request) -> Option<Response> + Send + Sync + 'static,
    {
        self.guard = Some(Arc::new(guard));
        self
    }
}

impl App {
    /// Serves one request, as `tower`'s `ServiceExt::oneshot` does, without the
    /// extension trait.
    ///
    /// # Errors
    ///
    /// Never fails: the error type is `Infallible`, kept for the shape of a service.
    pub async fn oneshot(self, request: Request) -> Result<Response, Infallible> {
        Ok(self.respond(request).await)
    }
}

impl tower::Service<Request> for App {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let app = self.clone();
        Box::pin(async move { Ok(app.respond(request).await) })
    }
}

/// Runs `app` on `listener`. The future resolves when the listener fails or
/// when the graceful shutdown signal, if any, completes and every connection has
/// finished.
#[must_use]
pub fn serve(listener: TcpListener, app: App) -> Serve {
    Serve {
        listener,
        app,
        shutdown: None,
    }
}

impl std::fmt::Debug for Serve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serve")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

/// A server, before it is run. Await it, or call [`Serve::with_graceful_shutdown`]
/// first.
pub struct Serve {
    listener: TcpListener,
    app: App,
    shutdown: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Serve {
    /// Stops accepting connections when `signal` completes, and returns once the
    /// open connections have finished.
    #[must_use]
    pub fn with_graceful_shutdown<F>(mut self, signal: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.shutdown = Some(Box::pin(signal));
        self
    }
}

impl IntoFuture for Serve {
    type Output = io::Result<()>;
    type IntoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(run(self.listener, self.app, self.shutdown))
    }
}

async fn run(
    listener: TcpListener,
    app: App,
    shutdown: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = shutdown.unwrap_or_else(|| Box::pin(std::future::pending()));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    // A failed accept (for example, out of file descriptors)
                    // should not stop the server: back off and try again.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let app = app.clone();
                let connection = http1::Builder::new().serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: http::Request<Incoming>| {
                        let app = app.clone();
                        async move {
                            let request = request.map(Body::from_incoming);
                            Ok::<_, Infallible>(app.respond(request).await)
                        }
                    }),
                );
                let connection = graceful.watch(connection);
                tokio::spawn(async move {
                    let _ = connection.await;
                });
            }
            () = &mut shutdown => break,
        }
    }
    graceful.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo(State(prefix): State<&'static str>, request: Request) -> String {
        let path = request.uri().path().to_owned();
        format!("{prefix}{path}")
    }

    fn app() -> App {
        Router::new()
            .route("/mcp", get(echo).post(echo))
            .route(
                "/json",
                get(|_: State<&'static str>, _: Request| async { Json(42) }),
            )
            .with_state("hi:")
    }

    #[tokio::test]
    async fn routes_by_exact_path_and_method() {
        let app = app();
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"hi:/mcp");
    }

    #[tokio::test]
    async fn unknown_path_is_404_and_unlisted_method_is_405() {
        let app = app();
        let missing = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let wrong = app
            .oneshot(
                http::Request::builder()
                    .method(Method::DELETE)
                    .uri("/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn json_responses_carry_their_content_type() {
        let response = app()
            .oneshot(
                http::Request::builder()
                    .uri("/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"42");
    }

    #[tokio::test]
    async fn to_bytes_enforces_the_limit() {
        let body = Body::from("0123456789");
        assert!(to_bytes(body, 5).await.is_err());
        let body = Body::from("0123456789");
        assert_eq!(&to_bytes(body, 10).await.unwrap()[..], b"0123456789");
    }

    #[test]
    fn events_encode_every_data_line() {
        let event = Event::default().id("7").event("message").data("a\nb");
        assert_eq!(
            &event.encode()[..],
            b"id: 7\nevent: message\ndata: a\ndata: b\n\n"
        );
    }

    #[tokio::test]
    async fn sse_responses_stream_events_then_end() {
        let events = futures::stream::iter(vec![
            Ok::<_, Infallible>(Event::default().id("1").data("one")),
            Ok(Event::default().id("2").data("two")),
        ]);
        let response = Sse::new(events).into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"id: 1\ndata: one\n\nid: 2\ndata: two\n\n");
    }

    #[tokio::test]
    async fn serve_answers_over_tcp_and_shuts_down_gracefully() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(
            serve(listener, app())
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .into_future(),
        );

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"GET /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut reply)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&reply);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.ends_with("hi:/mcp"), "{text}");

        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
