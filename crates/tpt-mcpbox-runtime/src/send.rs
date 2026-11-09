// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Sends one outbound HTTP request for a tool, after policy has admitted it.
//!
//! This replaces `wasmtime_wasi_http::default_send_request`, which is only built
//! with the `default-send-request` feature. That feature brings in `tokio-rustls`
//! with the `ring` provider, which is not allowed (todo.md, Phase 13). The steps
//! follow Wasmtime's version: connect under a timeout, run TLS for `https`,
//! handshake HTTP/1, send the request, and apply the first-byte and
//! between-bytes timeouts to the response body.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, uri::Scheme};
use http_body::Body;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use wasmtime_wasi_http::{Error, RequestOptions};

use crate::tls;

/// Timeout used for any phase whose option the request leaves unset.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// Where a request may go, and how much of the response it may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Egress {
    /// Tool traffic. Every address the name resolves to must be public, which
    /// stops an allowlisted name from reaching a host-internal service (SSRF,
    /// including cloud metadata). The response body is capped.
    Tool { max_response_bytes: u64 },
    /// Registry traffic, to a host the operator named in the configuration.
    /// Any address is allowed; the body is still capped.
    Registry { max_response_bytes: u64 },
}

impl Egress {
    fn max_response_bytes(self) -> u64 {
        match self {
            Self::Tool { max_response_bytes } | Self::Registry { max_response_bytes } => {
                max_response_bytes
            }
        }
    }
}

/// The response, and the future that drives the connection until it closes.
/// Wasmtime's hook contract expects this pair back.
pub(crate) type Sent = (
    Response<LimitBody<IdleBody>>,
    Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
);

/// Connection driver returned by the HTTP/1 handshake.
type Driver = Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>;

/// Send `request` and return its response, with the body wrapped so that each
/// gap between frames is bounded by the between-bytes timeout.
pub(crate) async fn send_request<B>(
    mut request: Request<B>,
    options: RequestOptions,
    egress: Egress,
) -> Result<Sent, Error>
where
    B: Body<Data = Bytes, Error = Error> + Send + 'static,
{
    let uri = request.uri().clone();
    let authority = uri.authority().ok_or(Error::HttpRequestUriInvalid)?;
    let use_tls = uri.scheme() == Some(&Scheme::HTTPS);
    let authority = if authority.port().is_some() {
        authority.to_string()
    } else {
        let port = if use_tls { 443 } else { 80 };
        format!("{authority}:{port}")
    };

    let connect_timeout = options.connect_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let first_byte_timeout = options.first_byte_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let between_bytes_timeout = options.between_bytes_timeout.unwrap_or(DEFAULT_TIMEOUT);

    let stream = match egress {
        Egress::Tool { .. } => connect_public(&authority, connect_timeout).await?,
        Egress::Registry { .. } => connect(&authority, connect_timeout).await?,
    };

    let (mut sender, conn): (hyper::client::conn::http1::SendRequest<B>, Driver) = if use_tls {
        let server_name = tls_server_name(&authority)?;
        let connector = tokio_rustls::TlsConnector::from(tls::client_config());
        let tls_stream =
            tokio::time::timeout(connect_timeout, connector.connect(server_name, stream))
                .await
                .map_err(|_| Error::ConnectionTimeout)?
                .map_err(Error::Tls)?;
        handshake(tls_stream, connect_timeout).await?
    } else {
        handshake(stream, connect_timeout).await?
    };

    // HTTP/1.1 requires a Host header, and the request line below loses the
    // authority, so supply it from the URI when the guest did not.
    if !request.headers().contains_key(http::header::HOST) {
        let host = http::HeaderValue::from_str(authority_text(&uri)?)
            .map_err(|_| Error::HttpRequestUriInvalid)?;
        request.headers_mut().insert(http::header::HOST, host);
    }

    // The request carries the scheme and authority, but HTTP/1 wants only the
    // path and query on the request line.
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            uri.path_and_query()
                .map(http::uri::PathAndQuery::as_str)
                .unwrap_or("/"),
        )
        .build()
        .map_err(|_| Error::HttpRequestUriInvalid)?;

    let send = async move {
        let response = tokio::time::timeout(first_byte_timeout, sender.send_request(request))
            .await
            .map_err(|_| Error::ConnectionReadTimeout)?
            .map_err(Error::from)?;
        Ok(response.map(|incoming| IdleBody::new(incoming, between_bytes_timeout)))
    };
    let mut send = pin!(send);
    let mut conn = Some(conn);

    // Drive the connection while waiting for the response headers.
    let response = poll_fn(|cx| {
        if let Poll::Ready(result) = send.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        let Some(fut) = conn.as_mut() else {
            return Poll::Pending;
        };
        match ready!(Pin::new(fut).poll(cx)) {
            Ok(()) => {
                conn = None;
                send.as_mut().poll(cx)
            }
            Err(err) => {
                conn = None;
                Poll::Ready(Err(Error::from(err)))
            }
        }
    })
    .await?;

    let io = Box::pin(async move {
        let Some(conn) = conn.take() else {
            return Ok(());
        };
        conn.await.map_err(|err| {
            if err.is_timeout() {
                Error::HttpResponseTimeout
            } else {
                Error::from(err)
            }
        })
    });
    let limit = egress.max_response_bytes();
    if let Some(declared) = crate::outbound::declared_length(response.headers())
        && declared > limit
    {
        return Err(Error::HttpResponseBodySize(Some(limit)));
    }
    Ok((response.map(|body| LimitBody::new(body, limit)), io))
}

/// Connects to `authority` under `timeout`.
async fn connect(authority: &str, timeout: Duration) -> Result<TcpStream, Error> {
    match tokio::time::timeout(timeout, TcpStream::connect(authority)).await {
        Ok(stream) => stream.map_err(Error::Connect),
        Err(..) => Err(Error::ConnectionTimeout),
    }
}

/// Resolves `authority`, refuses it when any address is host-internal, and
/// connects to the first address. Connecting to the address that was checked,
/// not to the name again, closes the window in which DNS could answer
/// differently the second time (rebinding).
async fn connect_public(authority: &str, timeout: Duration) -> Result<TcpStream, Error> {
    let addresses: Vec<SocketAddr> =
        match tokio::time::timeout(timeout, tokio::net::lookup_host(authority)).await {
            Ok(found) => found
                .map_err(|_| Error::DnsError {
                    rcode: None,
                    info_code: None,
                })?
                .collect(),
            Err(..) => return Err(Error::DnsTimeout),
        };
    if addresses.is_empty() {
        return Err(Error::DestinationNotFound);
    }
    if addresses
        .iter()
        .any(|address| crate::outbound::is_internal_address(address.ip()))
    {
        return Err(Error::DestinationIpProhibited);
    }
    connect(&addresses[0].to_string(), timeout).await
}

/// Caps a response body at `limit` bytes. A body that goes over is cut off with
/// [`Error::HttpResponseBodySize`], so a reply cannot make the host buffer an
/// arbitrarily large body.
pub(crate) struct LimitBody<B> {
    inner: B,
    limit: u64,
    seen: u64,
}

impl<B> LimitBody<B> {
    fn new(inner: B, limit: u64) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
        }
    }
}

impl<B> Body for LimitBody<B>
where
    B: Body<Data = Bytes, Error = Error> + Unpin,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.seen = self.seen.saturating_add(data.len() as u64);
                    if self.seen > self.limit {
                        let limit = self.limit;
                        return Poll::Ready(Some(Err(Error::HttpResponseBodySize(Some(limit)))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Run the HTTP/1 handshake over `io`, under the connect timeout.
async fn handshake<T, B>(
    io: T,
    timeout: Duration,
) -> Result<(hyper::client::conn::http1::SendRequest<B>, Driver), Error>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    B: Body<Data = Bytes, Error = Error> + Send + 'static,
{
    let (sender, conn) = tokio::time::timeout(
        timeout,
        hyper::client::conn::http1::Builder::new().handshake::<_, B>(TokioIo::new(io)),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)?
    .map_err(Error::from)?;
    Ok((sender, Box::pin(conn)))
}

/// The response body, with a between-bytes timeout: a gap longer than `limit`
/// with no frame ends the body with [`Error::ConnectionReadTimeout`].
pub(crate) struct IdleBody {
    inner: hyper::body::Incoming,
    idle: tokio::time::Interval,
}

impl IdleBody {
    fn new(inner: hyper::body::Incoming, limit: Duration) -> Self {
        // Tokio panics on a zero-length interval, so a zero limit becomes 1 ns.
        let limit = if limit.is_zero() {
            Duration::from_nanos(1)
        } else {
            limit
        };
        let mut idle = tokio::time::interval(limit);
        idle.reset();
        Self { inner, idle }
    }
}

impl Body for IdleBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => {
                let err = if err.is_timeout() {
                    Error::HttpResponseTimeout
                } else {
                    Error::from(err)
                };
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                self.idle.reset();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => {
                ready!(self.idle.poll_tick(cx));
                Poll::Ready(Some(Err(Error::ConnectionReadTimeout)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// The `host[:port]` text of a URI's authority, as written in the URI.
fn authority_text(uri: &http::Uri) -> Result<&str, Error> {
    uri.authority()
        .map(http::uri::Authority::as_str)
        .ok_or(Error::HttpRequestUriInvalid)
}

/// The name TLS verifies the certificate against, taken from `host:port`.
/// IPv6 literals keep their brackets stripped, and a port is never passed on.
fn tls_server_name(authority: &str) -> Result<ServerName<'static>, Error> {
    if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
        return Ok(ServerName::from(addr.ip()));
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host);
    ServerName::try_from(host)
        .map(|name| name.to_owned())
        .map_err(|_| Error::HttpRequestUriInvalid)
}

#[cfg(test)]
mod tests {
    use super::tls_server_name;
    use rustls::pki_types::ServerName;

    #[test]
    fn server_names_come_from_the_authority() {
        assert_eq!(
            tls_server_name("example.com:443").unwrap(),
            ServerName::try_from("example.com").unwrap()
        );
        assert_eq!(
            tls_server_name("example.com").unwrap(),
            ServerName::try_from("example.com").unwrap()
        );
        assert_eq!(
            tls_server_name("127.0.0.1:443").unwrap(),
            ServerName::from(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            tls_server_name("[::1]:443").unwrap(),
            ServerName::from(std::net::Ipv6Addr::LOCALHOST)
        );
    }
}

#[cfg(test)]
mod egress_tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use wasmtime_wasi_http::Error;

    use super::{LimitBody, connect_public};

    #[tokio::test]
    async fn tool_connections_refuse_host_internal_addresses_before_connecting() {
        for authority in [
            "127.0.0.1:443",
            "localhost:443",
            "169.254.169.254:80",
            "[::1]:443",
        ] {
            let error = connect_public(authority, Duration::from_secs(5))
                .await
                .expect_err(authority);
            assert!(
                matches!(error, Error::DestinationIpProhibited),
                "{authority}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_over_its_limit_is_cut_off() {
        let body = Full::new(Bytes::from_static(b"0123456789"))
            .map_err(|never: Infallible| match never {});
        let mut capped = LimitBody::new(body, 4);
        let frame = capped.frame().await.expect("a frame");
        assert!(
            matches!(frame, Err(Error::HttpResponseBodySize(Some(4)))),
            "a body of 10 bytes must not pass a limit of 4"
        );
    }

    #[tokio::test]
    async fn a_body_within_its_limit_passes_unchanged() {
        let body =
            Full::new(Bytes::from_static(b"abcd")).map_err(|never: Infallible| match never {});
        let mut capped = LimitBody::new(body, 4);
        let frame = capped.frame().await.expect("a frame").expect("no error");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"abcd")
        );
    }
}
