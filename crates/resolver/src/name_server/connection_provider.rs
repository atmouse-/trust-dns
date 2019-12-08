// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Future, FutureExt};
use tokio;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;
#[cfg(all(
    feature = "dns-over-openssl",
    not(feature = "dns-over-rustls"),
    not(feature = "dns-over-native-tls")
))]
use tokio_openssl::SslStream as TokioTlsStream;
#[cfg(feature = "dns-over-rustls")]
use tokio_rustls::client::TlsStream as TokioTlsStream;
#[cfg(all(feature = "dns-over-native-tls", not(feature = "dns-over-rustls")))]
use tokio_tls::TlsStream as TokioTlsStream;

use proto;
use proto::error::ProtoError;
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};
use proto::op::NoopMessageFinalizer;
use proto::tcp::{TcpClientConnect, TcpClientStream};
use proto::udp::{UdpClientConnect, UdpClientStream, UdpResponse};
use proto::xfer::{
    DnsExchange, DnsExchangeBackground, DnsExchangeConnect, DnsExchangeSend, DnsHandle,
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse, DnsRequest, DnsResponse,
};

#[cfg(feature = "dns-over-https")]
use trust_dns_https::{self, HttpsClientConnect, HttpsClientResponse, HttpsClientStream};

use crate::config::{NameServerConfig, Protocol, ResolverOpts};

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    type Conn: DnsHandle + Clone + Send + 'static;
    type Background: Future<Output = Result<(), ProtoError>> + Send + 'static;
    type FutureConn: Future<Output = Result<(Self::Conn, Option<Self::Background>), ProtoError>>
        + Clone
        + Send
        + 'static;

    /// The returned handle should
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::FutureConn;
}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct StandardConnection;

impl ConnectionProvider for StandardConnection {
    type Conn = Connection;
    type Background = ConnectionBackground;
    type FutureConn = StandardConnectionFuture;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::FutureConn {
        let dns_connect = match config.protocol {
            Protocol::Udp => {
                let stream = UdpClientStream::<TokioUdpSocket>::with_timeout(
                    config.socket_addr,
                    options.timeout,
                );
                let exchange = DnsExchange::connect(stream);
                ConnectionConnect::Udp(exchange)
            }
            Protocol::Tcp => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;

                let (stream, handle) =
                    TcpClientStream::<TokioTcpStream>::with_timeout(socket_addr, timeout);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    Box::new(stream),
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tcp(exchange)
            }
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();

                #[cfg(feature = "dns-over-rustls")]
                let (stream, handle) =
                    { crate::tls::new_tls_stream(socket_addr, tls_dns_name, client_config) };
                #[cfg(not(feature = "dns-over-rustls"))]
                let (stream, handle) = { crate::tls::new_tls_stream(socket_addr, tls_dns_name) };

                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    Box::new(handle),
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tls(exchange)
            }
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => {
                let socket_addr = config.socket_addr;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();

                let exchange =
                    crate::https::new_https_stream(socket_addr, tls_dns_name, client_config);
                ConnectionConnect::Https(exchange)
            }
            #[cfg(feature = "mdns")]
            Protocol::Mdns => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;

                let (stream, handle) =
                    MdnsClientStream::new(socket_addr, MdnsQueryType::OneShot, None, None, None);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Mdns(exchange)
            }
        };

        StandardConnectionFuture(dns_connect)
    }
}

/// The variants of all supported connections for the Resolver
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub(crate) enum ConnectionConnect {
    Udp(
        DnsExchangeConnect<
            UdpClientConnect<TokioUdpSocket>,
            UdpClientStream<TokioUdpSocket>,
            UdpResponse,
        >,
    ),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Box<TcpClientConnect<TokioTcpStream>>,
                TcpClientStream<TokioTcpStream>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TcpClientStream<TokioTcpStream>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
    #[cfg(feature = "dns-over-tls")]
    Tls(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Pin<
                    Box<
                        dyn futures::Future<
                                Output = Result<
                                    TcpClientStream<TokioTlsStream<TokioTcpStream>>,
                                    ProtoError,
                                >,
                            > + Send
                            + 'static,
                    >,
                >,
                TcpClientStream<TokioTlsStream<TokioTcpStream>>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TcpClientStream<TokioTlsStream<TokioTcpStream>>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeConnect<HttpsClientConnect, HttpsClientStream, HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(
        DnsExchangeConnect<
            DnsMultiplexerConnect<MdnsClientConnect, MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexer<MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
}

/// Resolves to a new Connection
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct StandardConnectionFuture(ConnectionConnect);

impl Future for StandardConnectionFuture {
    type Output = Result<(Connection, Option<ConnectionBackground>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let connection = match &mut self.0 {
            ConnectionConnect::Udp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = Connection(ConnectionConnected::Udp(conn));
                let bg = bg
                    .map(ConnectionBackgroundInner::Udp)
                    .map(ConnectionBackground);
                (conn, bg)
            }
            ConnectionConnect::Tcp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = Connection(ConnectionConnected::Tcp(conn));
                let bg = bg
                    .map(ConnectionBackgroundInner::Tcp)
                    .map(ConnectionBackground);
                (conn, bg)
            }
            #[cfg(feature = "dns-over-tls")]
            ConnectionConnect::Tls(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = Connection(ConnectionConnected::Tls(conn));
                let bg = bg
                    .map(ConnectionBackgroundInner::Tls)
                    .map(ConnectionBackground);
                (conn, bg)
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionConnect::Https(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = Connection(ConnectionConnected::Https(conn));
                let bg = bg
                    .map(ConnectionBackgroundInner::Https)
                    .map(ConnectionBackground);
                (conn, bg)
            }
            #[cfg(feature = "mdns")]
            ConnectionConnect::Mdns(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = Connection(ConnectionConnected::Mdns(conn));
                let bg = bg
                    .map(ConnectionBackgroundInner::Mdns)
                    .map(ConnectionBackground);
                (conn, bg)
            }
        };

        Poll::Ready(Ok(connection))
    }
}

/// A connected DNS handle
#[derive(Clone)]
pub struct Connection(ConnectionConnected);

impl DnsHandle for Connection {
    type Response = ConnectionResponse;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        self.0.send(request)
    }
}

/// A representation of an established connection
#[derive(Clone)]
enum ConnectionConnected {
    Udp(DnsExchange<UdpResponse>),
    Tcp(DnsExchange<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-tls")]
    Tls(DnsExchange<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchange<HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(DnsExchange<DnsMultiplexerSerialResponse>),
}

impl DnsHandle for ConnectionConnected {
    type Response = ConnectionResponse;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        let response = match self {
            ConnectionConnected::Udp(ref mut conn) => {
                ConnectionResponseInner::Udp(conn.send(request))
            }
            ConnectionConnected::Tcp(ref mut conn) => {
                ConnectionResponseInner::Tcp(conn.send(request))
            }
            #[cfg(feature = "dns-over-tls")]
            ConnectionConnected::Tls(ref mut conn) => {
                ConnectionResponseInner::Tls(conn.send(request))
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionConnected::Https(ref mut https) => {
                ConnectionResponseInner::Https(https.send(request))
            }
            #[cfg(feature = "mdns")]
            ConnectionConnected::Mdns(ref mut mdns) => {
                ConnectionResponseInner::Mdns(mdns.send(request))
            }
        };

        ConnectionResponse(response)
    }
}

/// A wrapper type to switch over a connection that still needs to be made, or is already established
#[must_use = "futures do nothing unless polled"]
enum ConnectionResponseInner {
    Udp(DnsExchangeSend<UdpResponse>),
    Tcp(DnsExchangeSend<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-tls")]
    Tls(DnsExchangeSend<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeSend<HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(DnsExchangeSend<DnsMultiplexerSerialResponse>),
}

impl Future for ConnectionResponseInner {
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use self::ConnectionResponseInner::*;

        trace!("polling response inner");
        match *self {
            Udp(ref mut resp) => resp.poll_unpin(cx),
            Tcp(ref mut resp) => resp.poll_unpin(cx),
            #[cfg(feature = "dns-over-tls")]
            Tls(ref mut tls) => tls.poll_unpin(cx),
            #[cfg(feature = "dns-over-https")]
            Https(ref mut https) => https.poll_unpin(cx),
            #[cfg(feature = "mdns")]
            Mdns(ref mut mdns) => mdns.poll_unpin(cx),
        }
    }
}

/// A future response from a DNS request.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionResponse(ConnectionResponseInner);

impl Future for ConnectionResponse {
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

/// A background task for driving the DNS protocol of the connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionBackground(ConnectionBackgroundInner);

impl Future for ConnectionBackground {
    type Output = Result<(), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

#[allow(clippy::large_enum_variant)]
#[allow(clippy::type_complexity)]
#[must_use = "futures do nothing unless polled"]
pub(crate) enum ConnectionBackgroundInner {
    Udp(DnsExchangeBackground<UdpClientStream<TokioUdpSocket>, UdpResponse>),
    Tcp(
        DnsExchangeBackground<
            DnsMultiplexer<TcpClientStream<TokioTcpStream>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
    #[cfg(feature = "dns-over-tls")]
    Tls(
        DnsExchangeBackground<
            DnsMultiplexer<TcpClientStream<TokioTlsStream<TokioTcpStream>>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeBackground<HttpsClientStream, HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(
        DnsExchangeBackground<
            DnsMultiplexer<MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
        >,
    ),
}

impl Future for ConnectionBackgroundInner {
    type Output = Result<(), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use self::ConnectionBackgroundInner::*;

        trace!("polling response inner");
        match *self {
            Udp(ref mut bg) => bg.poll_unpin(cx),
            Tcp(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "dns-over-tls")]
            Tls(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "dns-over-https")]
            Https(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "mdns")]
            Mdns(ref mut bg) => bg.poll_unpin(cx),
        }
    }
}
