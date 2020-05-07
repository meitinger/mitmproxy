from __future__ import annotations
import asyncio
import collections
import enum
import functools
import ssl
import socket
import sys
import time
import traceback
from email.utils import formatdate
from typing import (
    cast,
    Callable,
    Coroutine,
    Deque,
    Dict,
    List,
    Tuple,
    Optional,
    Set,
    Type,
    Union,
)

import mitmproxy
from mitmproxy import certs
from mitmproxy import connections
from mitmproxy import controller
from mitmproxy import exceptions
from mitmproxy import flow as baseflow
from mitmproxy import http
from mitmproxy import log
from mitmproxy import options as moptions
from mitmproxy import proxy
from mitmproxy import tcp
from mitmproxy import websocket
from mitmproxy.net.http import url

import OpenSSL
import wsproto

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    rsa,
)
from cryptography.hazmat.primitives.serialization import Encoding

from ..net.tls import log_master_secret
from ..version import VERSION


import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection, ProtocolError, FrameUnexpected
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    Headers,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionError
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)
from aioquic.quic.packet import QuicErrorCode
from aioquic.tls import (
    ClientHello,
    Context as TlsContext,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
)


HttpConnection = Union[H0Connection, H3Connection]

SERVER_NAME = "mitmproxy/" + VERSION


class KnownPseudoHeaders(enum.Enum):
    method = 1
    scheme = 2
    authority = 3
    path = 4
    protocol = 5


class LogLevel(enum.Enum):
    debug = 1
    info = 2
    alert = 3
    warn = 4
    error = 5


class ProxyMode(enum.Enum):
    regular = 1
    upstream = 2
    reverse = 3
    transparent = 4


class ProxySide(enum.IntEnum):
    client = 0
    server = 1

    @property
    def other_side(self) -> ProxySide:
        return ProxySide.server if self is ProxySide.client else ProxySide.client


class FlowError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ProxyContext:
    def __init__(self, config: proxy.ProxyConfig, channel: controller.Channel) -> None:
        self.upstream_or_reverse_address: Tuple[bytes, int]
        self.options: moptions.Options = config.options
        self._config = config
        self._channel = channel

        # parse the proxy mode
        parts = config.options.mode.split(":", 1)
        try:
            self.mode = ProxyMode[parts[0]]
        except KeyError:
            raise exceptions.OptionsError(f"Unsupported proxy mode: {parts[0]}")
        if self.mode is ProxyMode.upstream or self.mode is ProxyMode.reverse:
            _, host, port, _ = url.parse(parts[1])
            self.upstream_or_reverse_address = (host, port)
        elif len(parts) > 1:
            raise exceptions.OptionsError(
                f"Only upstream and reverse proxies take urls, not {self.mode.name} proxies."
            )

    async def ask(self, mtype, m):
        if not self._channel.should_exit.is_set():
            m.reply = controller.Reply(m)
            if asyncio.get_event_loop() is self._channel.loop:
                await self._channel.master.addons.handle_lifecycle(mtype, m)
            else:
                await asyncio.run_coroutine_threadsafe(
                    self._channel.master.addons.handle_lifecycle(mtype, m),
                    self._channel.loop,
                ).result()
            g = m.reply.q.get(block=False)
            if g == exceptions.Kill:
                raise exceptions.Kill()
            return g

    def convert_certificate(self, certificate: x509.Certificate) -> certs.Cert:
        return certs.Cert.from_pem(certificate.public_bytes(Encoding.PEM))

    def generate_certificate(
        self,
        commonname: Optional[bytes],
        sans: Set[bytes],
        organization: Optional[bytes] = None,
        extra_chain: Optional[List[certs.Cert]] = None,
    ) -> Tuple[
        x509.Certificate,
        List[x509.Certificate],
        Union[dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    ]:
        cert, private_key, chain_file = self._config.certstore.get_cert(
            commonname, list(sans), organization
        )
        with open(chain_file, "rb") as fp:
            chain = load_pem_x509_certificates(fp.read())
        if extra_chain is not None:
            for extra_cert in extra_chain:
                chain.append(
                    load_pem_x509_certificates(
                        OpenSSL.crypto.dump_certificate(
                            OpenSSL.crypto.FILETYPE_PEM, extra_cert.x509
                        )
                    )
                )
        return (
            load_pem_x509_certificates(
                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.x509)
            )[0],
            chain,
            load_pem_private_key(
                OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM, private_key
                ),
                None,
            ),
        )

    def log(
        self,
        type: str,
        from_addr: Tuple[str, int],
        to_addr: Tuple[str, int],
        level: LogLevel,
        msg: str,
        additional: Optional[Dict[str, str]] = None,
    ) -> None:
        msg = f"[QUIC-{type}] {from_addr[0]}:{from_addr[1]} -> {to_addr}: {msg}"
        if additional is not None:
            msg = ("\n" + " " * 6).join(
                [msg] + [f"{name}: {value}" for (name, value) in additional.items()]
            )
        self.tell("log", log.LogEntry(msg, level.name))

    def tell(self, mtype, m):
        if not self._channel.should_exit.is_set():
            m.reply = controller.DummyReply()
            asyncio.run_coroutine_threadsafe(
                self._channel.master.addons.handle_lifecycle(mtype, m),
                self._channel.loop,
            )


class ConnectionProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        client: IncomingProtocol,
        server: Optional[OutgoingProtocol],
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._side: ProxySide
        self._push_bridges: Dict[int, Bridge] = {}
        self._bridges: Dict[int, Bridge] = {}
        self._http: Optional[HttpConnection] = None
        self._local_close: bool = False
        self._client: IncomingProtocol = client
        self._server: Optional[OutgoingProtocol] = server

        # determine the side
        if self is client:
            self._side = ProxySide.client
        elif self is server:
            self._side = ProxySide.server
        else:
            raise ValueError(
                "The current connection must either be the client or server connection."
            )

    @property
    def address(self) -> Tuple[str, int]:
        return self._quic._network_paths[0].addr[0:2]

    @address.setter
    def address(self, address):
        if address is not None:
            raise PermissionError

    @property
    def context(self) -> ProxyContext:
        return self._client.context

    def _handle_connection_terminated(self, event: ConnectionTerminated) -> None:
        # note the time and log the event
        self.timestamp_end = time.time()
        self.log(
            LogLevel.info
            if event.error_code == QuicErrorCode.NO_ERROR
            else LogLevel.warn,
            "Connection closed.",
            {
                "error_code": event.error_code,
                "frame_type": event.frame_type,
                "reason_phrase": event.reason_phrase,
                "by_peer": not self._local_close,
            },
        )

        # close the server connection (if any) as well
        if self._side is ProxySide.client and self._server is not None:
            self._server.close(
                error_code=event.error_code,
                frame_type=event.frame_type,
                reason_phrase=event.reason_phrase,
            )

    def _handle_http_data_received(self, event: DataReceived) -> None:
        event_description = {
            "stream_id": event.stream_id,
            "stream_ended": event.stream_ended,
            "data_length": len(event.data),
        }
        if event.stream_id not in self._bridges:
            self.log(
                LogLevel.warn, "Data received without prior headers.", event_description
            )
            return
        bridge = self._bridges[event.stream_id]
        bridge.post_data(self._side, event.data)

    def _handle_http_headers_received(self, event: HeadersReceived) -> None:
        if event.stream_id not in self._bridges:
            self._bridges[event.stream_id] = HttpBridge(
                client=self._client,
                server=self._server,
                stream_id=event.stream_id,
                headers=event.headers,
            )
        else:
            bridge = self._bridges[event.stream_id]
            bridge.post_data(self._side, event.headers, is_header=True)

    def _handle_http_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            if event.push_id is None:
                self._handle_http_headers_received(event)
            else:
                self._handle_http_push_data_or_trailers_received(event, is_data=True)
        elif isinstance(event, DataReceived):
            if event.push_id is None:
                self._handle_http_data_received(event)
            else:
                self._handle_http_push_data_or_trailers_received(event, is_data=False)
        elif isinstance(event, PushPromiseReceived):
            self._handle_http_push_promise_received(event)
        else:
            self.log(
                LogLevel.warn,
                "Unknown H3Event received",
                {"type": type(event).__name__},
            )

    def _handle_http_push_data_or_trailers_received(
        self, event: Union[DataReceived, HeadersReceived], is_data: bool
    ) -> None:
        event_description = {
            "type": "data" if is_data else "trailers",
            "stream_id": event.stream_id,
            "stream_ended": event.stream_ended,
            "push_id": event.push.id,
        }
        if self._side is ProxySide.client:
            self.log(
                LogLevel.warn, "Push data received from client.", event_description
            )
            return
        if event.push_id not in self._push_bridges:
            self.log(
                LogLevel.warn,
                "Push data received without prior promise.",
                event_description,
            )
            return
        bridge = self._push_bridges[event.push_id]
        if bridge.has_server_stream_id():
            if bridge.server_stream_id != event.stream_id:
                self.log(
                    LogLevel.warn,
                    "Push data received on different stream.",
                    event_description + {"push_stream_id": bridge.server_stream_id},
                )
                return
        else:
            if event.stream_id in self._bridges:
                self.log(
                    LogLevel.warn,
                    "Push data received on already assigned stream.",
                    event_description,
                )
                return
            bridge.server_stream_id = event.stream_id
            self._bridges[event.stream_id] = bridge  # necessary for stream reset
        bridge.post_data(
            ProxySide.server,
            event.data if is_data else event.headers,
            is_header=not is_data,
        )

    def _handle_http_push_promise_received(self, event: PushPromiseReceived) -> None:
        event_description = {
            "stream_id": event.stream_id,
            "push_id": event.push.id,
        }
        if self._side is ProxySide.client:
            # log and exit
            self.log(
                LogLevel.warn, "Push promise received from client.", event_description
            )
            return
        if event.stream_id not in self._bridges:
            # a bidirectional channel is needed
            self.log(
                LogLevel.warn,
                "Push promise received on unknown stream.",
                event_description,
            )
            return
        if event.push_id in self._push_bridges:
            # log and exit
            self.log(
                LogLevel.warn, "Duplicate push promise received.", event_description
            )
            return
        self._push_bridges[event.push_id] = HttpBridge(
            client=self._client,
            server=self._server,
            stream_id=event.stream_id,
            headers=event.headers,
            push_id=event.push_id,
            push_promise_to=self._bridges[event.stream_id],
        )

    def _handle_raw_stream_data(self, event: StreamDataReceived) -> None:
        # create or get the bridge and post the data
        bridge: RawBridge
        if not event.stream_id in self._bridges:
            # raw data can't be routed like a regular proxy request
            if not self._server:
                self.log(
                    LogLevel.warn,
                    "Received raw data without server connection.",
                    {
                        "stream_id": event.stream_id,
                        "data_length": len(event.data),
                        "end_stream": event.end_stream,
                    },
                )
                return
            bridge = RawBridge(
                client=self._client,
                client_stream_id=event.stream_id,
                server=self._server,
                server_stream_id=self._server._quic.get_next_available_stream_id(),
            )
        else:
            bridge = cast(RawBridge, self._bridges[event.stream_id])
        bridge.post_data(self._side, event.data)

    def _handle_stream_reset(self, event: StreamReset) -> None:
        # end the stream like an ordinary FIN would
        if not event.stream_id in self._bridges:
            self.log(
                LogLevel.info,
                "Received reset for unknown stream.",
                {"stream_id": event.stream_id},
            )
            return
        bridge = self._bridges[event.stream_id]
        bridge.end_stream(self._side)

    def close(
        self,
        error_code: int = QuicErrorCode.NO_ERROR,
        frame_type: Optional[int] = None,
        reason_phrase: str = "",
    ) -> None:
        # override and allow a more detailed close
        self._local_close = True
        self._quic.close(
            error_code=error_code, frame_type=frame_type, reason_phrase=reason_phrase
        )
        self.transmit()

    def connected(self) -> bool:
        return not self._closed.is_set()

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        # set the proper http connection
        if event.alpn_protocol.startswith("h3-"):
            self._http = H3Connection(self._quic)
        elif event.alpn_protocol.startswith("hq-"):
            self._http = H0Connection(self._quic)

        # store the security details
        self.alpn_proto_negotiated = event.alpn_protocol.encode()
        self.cipher_name = event.cipher_name
        self.timestamp_tls_setup = time.time()
        self.tls_established = True
        self.tls_version = "TLSv1.3"

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        raise NotImplementedError

    def quic_event_received(self, event: QuicEvent) -> None:
        try:
            try:
                # handle known events
                if isinstance(event, HandshakeCompleted):
                    self.handshake_complete(event)
                elif isinstance(event, ConnectionTerminated):
                    self._handle_connection_terminated(event)
                elif isinstance(event, StreamReset):
                    self._handle_stream_reset(event)
                elif isinstance(event, StreamDataReceived):
                    if self._http is None:
                        self._handle_raw_stream_data(event)
                    else:
                        for http_event in self._http.handle_event(event):
                            self._handle_http_event(http_event)
                    if event.end_stream and event.stream_id in self._bridges:
                        self._bridges[event.stream_id].end_stream(self._side)
            except Exception as exc:
                self.log(
                    LogLevel.error,
                    "Exception during event handling.",
                    {
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "stacktrace": "\n" + traceback.format_exc(),
                    },
                )
        except:
            # when even logging fails
            traceback.print_exc(file=sys.stderr)


class OutgoingProtocol(ConnectionProtocol, connections.ServerConnection):
    def __init__(self, client: IncomingProtocol, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, client, self, *args, **kwargs)
        connections.ServerConnection.__init__(self, None, None, None)

    @property
    def source_address(self) -> Tuple[str, int]:
        return self._transport.get_extra_info("sockname")[0:2]

    @source_address.setter
    def source_address(self, source_address):
        if source_address is not None:
            raise PermissionError

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        self.context.log(
            "out", self.source_address, self.address, level, msg, additional
        )

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        super().handshake_complete(event)
        self.cert = self.context.convert_certificate(event.certificates[0])
        self.server_certs = [
            self.context.convert_certificate(cert) for cert in event.certificates[1:]
        ]


class IncomingProtocol(ConnectionProtocol, connections.ClientConnection):
    def __init__(self, context: ProxyContext, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, self, None, *args, **kwargs)
        connections.ClientConnection.__init__(self, None, None, None)
        self._context: ProxyContext = context
        orig_initialize = self._quic._initialize

        def initialize_replacement(*args, **kwargs):
            try:
                return orig_initialize(*args, **kwargs)
            finally:
                self._quic.tls.client_hello_cb = self._handle_client_hello

        self._quic._initialize = initialize_replacement

    @property
    def context(self) -> ProxyContext:
        return self._context

    @property
    def server(self) -> Tuple[str, int]:
        orig_dst = self._quic._network_paths[0].orig_dst
        if orig_dst is None:
            orig_dst = self._transport.get_extra_info("sockname")
        if orig_dst[0] == "::":
            return ("::1", orig_dst[1])
        elif orig_dst[0] == "0.0.0.0":
            return ("127.0.0.1", orig_dst[1])
        else:
            return orig_dst[0:2]

    @server.setter
    def server(self, server):
        if server is not None:
            raise PermissionError

    async def _create_outgoing_protocol(
        self,
        *,
        remote_addr=Tuple[str, int],
        sni: Optional[str],
        alpn_protocols: List[str],
    ) -> OutgoingProtocol:
        connection = QuicConnection(
            configuration=QuicConfiguration(
                alpn_protocols=alpn_protocols,
                is_client=True,
                server_name=sni,
                secrets_log_file=log_master_secret,
                verify_mode=ssl.CERT_NONE
                if self.context.options.ssl_insecure
                else ssl.CERT_REQUIRED,
                cafile=self.context.options.ssl_verify_upstream_trusted_ca,
                capath=self.context.options.ssl_verify_upstream_trusted_confdir,
            )
        )
        if self.context.options.spoof_source_address:
            self.log(LogLevel.info, "Source address spoofing not yet supported.")
        _, protocol = await self._loop.create_datagram_endpoint(
            functools.partial(OutgoingProtocol, self, connection),
            local_addr=(self.context.options.listen_host or "::", 0),
        )
        protocol = cast(QuicConnectionProtocol, protocol)
        protocol.connect(remote_addr)
        await protocol.wait_connected()
        return protocol

    def _handle_client_hello(self, hello: ClientHello) -> None:
        tls: TlsContext = self._quic.tls
        host: bytes = None
        sans: Set = set()
        organization: Optional[str] = None
        extra_chain: Optional[List[certs.Cert]] = None

        # store the sni
        self.sni = (
            None if hello.server_name is None else hello.server_name.encode("idna")
        )

        # create the outgoing connection if possible
        # NOTE: This is a derivation to mitmproxy's default behavior. Mitmproxy only initiates a connection
        #       if it is necessary, e.g. if `upstream_cert` is set. Otherwise it allows to replay an entire
        #       flow. However, in order to allow the inspection of any stream data, this would require
        #       something like `ask("alpn_protocol", flow)` to also record and replay the selected protocol.
        if self.context.mode is not ProxyMode.regular:
            self._server = asyncio.run_coroutine_threadsafe(
                self._create_outgoing_protocol(
                    remote_addr=self.server
                    if self.context.mode is ProxyMode.transparent
                    else (
                        self.context.upstream_or_reverse_address[0].decode("idna"),
                        self.context.upstream_or_reverse_address[1],
                    ),
                    sni=hello.server_name,
                    alpn_protocols=hello.alpn_protocols,
                ),
                self._loop,
            ).result()
            tls.alpn_negotiated = self._server.alpn_proto_negotiated.decode()

            # copy over all possible certificate data if requested
            if self.context.options.upstream_cert:
                upstream_cert = self._server.cert
                sans.update(upstream_cert.altnames)
                if upstream_cert.cn:
                    host = upstream_cert.cn.decode("utf8").encode("idna")
                    sans.add(host)
                if upstream_cert.organization:
                    organization = upstream_cert.organization
            if self.context.options.add_upstream_certs_to_client_chain:
                extra_chain = self._server.server_certs

        # add the name of server name of the reverse target or upstream proxy
        if (
            self.context.mode is ProxyMode.upstream
            or self.context.mode is ProxyMode.reverse
        ):
            upstream_or_reverse_host = self.context.upstream_or_reverse_address[0]
            sans.add(upstream_or_reverse_host)
            if host is None:
                host = upstream_or_reverse_host

        # add the wanted server name (even if the client wants that name, do not override upstream_cert host)
        if self.sni is not None:
            sans.add(self.sni)
            if host is None:
                host = self.sni

        # as a last resort, add the ip
        if host is None:
            host = self.server[0].encode("idna")
            sans.add(host)

        # build the certificate, possibly adding extra certs and store the OpenSSL cert
        (
            tls.certificate,
            tls.certificate_chain,
            tls.certificate_private_key,
        ) = self.context.generate_certificate(
            host, list(sans), organization, extra_chain=extra_chain,
        )

    def _process_events_and_transmit(self, future: asyncio.Future) -> None:
        try:
            future.result()
            self._process_events()
            self.transmit()
        except:
            traceback.print_exc(file=sys.stderr)

    def datagram_received(
        self, data: bytes, addr: Tuple, orig_dst: Optional[Tuple] = None
    ) -> None:
        if self.tls_established:
            try:
                self._quic.receive_datagram(
                    cast(bytes, data), addr, self._loop.time(), orig_dst
                )
                self._process_events()
                self.transmit()
            except:
                traceback.print_exc(file=sys.stderr)
        else:
            # everything before the handshake must happen in a different thread
            # to support blocking for the client, since QuicConnection is not async
            self._loop.run_in_executor(
                None,
                self._quic.receive_datagram,
                bytes(data),
                addr,
                self._loop.time(),
                orig_dst,
            ).add_done_callback(self._process_events_and_transmit)

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        super().handshake_complete(event)
        self.mitmcert = self.context.convert_certificate(event.certificates[0])

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        self.context.log("in", self.address, self.server, level, msg, additional)


class Bridge:
    def __init__(
        self,
        proto: Tuple[IncomingProtocol, Optional[OutgoingProtocol]],
        stream_id: Tuple[int, Optional[int]],
    ):
        self._proto: Tuple[IncomingProtocol, Optional[OutgoingProtocol]] = proto
        self._stream_id: Tuple[int, Optional[int]] = stream_id
        self._stream_ended: Tuple[asyncio.Event, asyncio.Event] = (
            asyncio.Event(),
            asyncio.Event(),
        )
        self._sent_end_stream: Tuple[bool, bool] = (False, False)
        asyncio.ensure_future(self._internal_run())

    async def _internal_run(self) -> None:
        try:
            try:
                # run the bridge and ensure the streams have been ended
                try:
                    await self.run()
                finally:
                    for side in ProxySide:
                        if (
                            (side is ProxySide.client or self.has_server_stream_id())
                            and not self.is_connection_closed(side)
                            and not self.has_sent_end_stream(side)
                        ):
                            # TODO: replace with sending RESET_STREAM once aioquic supports it
                            proto = self.proto(side)
                            proto._quic.send_stream_data(
                                stream_id=self.stream_id(side),
                                data=b"",
                                end_stream=True,
                            )
                            proto.transmit()
            except Exception as exc:
                self.log(
                    LogLevel.error,
                    "Exception while running bridge.",
                    {
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "stacktrace": "\n" + traceback.format_exc(),
                    },
                )
        except:
            # when even logging fails
            traceback.print_exc(file=sys.stderr)

    @property
    def client(self) -> IncomingProtocol:
        return cast(IncomingProtocol, self.proto(ProxySide.client))

    @property
    def context(self) -> ProxyContext:
        return self.client.context

    def are_all_connections_closed(self) -> bool:
        return self.is_connection_closed(
            ProxySide.client
        ) and self.is_connection_closed(ProxySide.server)

    def end_stream(self, side: ProxySide) -> None:
        self._stream_ended[side.value].set()

    def has_sent_end_stream(self, side: ProxySide) -> bool:
        return self._sent_end_stream[side.value]

    def has_server(self) -> bool:
        return self._proto[1] is not None

    def has_server_stream_id(self) -> bool:
        return self._stream_id[1] is not None

    def has_stream_ended(self, side: ProxySide) -> bool:
        return self._stream_ended[side.value].is_set()

    def has_any_stream_ended(self) -> bool:
        return self.has_stream_ended(ProxySide.client) or self.has_stream_ended(
            ProxySide.server
        )

    def have_all_streams_ended(self) -> bool:
        return self.has_stream_ended(ProxySide.client) and self.has_stream_ended(
            ProxySide.server
        )

    def is_any_connection_closed(self) -> bool:
        return self.is_connection_closed(ProxySide.client) or self.is_connection_closed(
            ProxySide.server
        )

    def is_connection_closed(self, side: ProxySide) -> bool:
        return not self.proto(side).connected()

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        self.context.log(
            "bridge",
            self.client.address,
            self.server.address if self.has_server() else self.client.server,
            level,
            msg,
            additional,
        )

    def proto(self, side: ProxySide) -> ConnectionProtocol:
        proto = self._proto[side.value]
        if proto is None:
            raise FlowError(
                500,
                f"{'Client' if side is ProxySide.client else 'Server'} protocol not set.",
            )
        return proto

    async def run(self) -> None:
        pass

    def send(
        self,
        side: ProxySide,
        cb: Callable[[ConnectionProtocol, int], None],
        end_stream: bool = False,
    ) -> None:
        # ensure the connection is open and no end_stream was sent
        if self.is_connection_closed(side):
            raise FlowError(
                502,
                f"{'Client' if side is ProxySide.client else 'Server'} connection already closed.",
            )
        if self.has_sent_end_stream(side):
            raise FlowError(
                500,
                f"{'Client' if side is ProxySide.client else 'Server'} stream has already been ended by proxy.",
            )

        # send and transmit
        proto = self.proto(side)
        stream_id = self.stream_id(side)
        cb(proto, stream_id)
        if end_stream:
            proto._quic.send_stream_data(stream_id, b"", end_stream=True)
            sent_end_stream = list(self._sent_end_stream)
            sent_end_stream[side.value] = True
            self._sent_end_stream = tuple(sent_end_stream)
        proto.transmit()

    @property
    def server(self) -> OutgoingProtocol:
        return cast(OutgoingProtocol, self.proto(ProxySide.server))

    @server.setter
    def server(self, server: OutgoingProtocol) -> None:
        if server is None:
            raise ValueError("Server protocol must not be None.")
        if self.has_server():
            raise AttributeError("Server protocol already set.")
        self._proto = (self._proto[0], server)

    @property
    def server_stream_id(self) -> int:
        return self.stream_id(ProxySide.server)

    @server_stream_id.setter
    def server_stream_id(self, server_stream_id: int) -> None:
        if server_stream_id is None:
            raise ValueError("Server stream_id must not be None.")
        if self.has_server_stream_id():
            raise AttributeError("Server stream_id already set.")
        self._stream_id = (self._stream_id[0], server_stream_id)

    def stream_id(self, side: ProxySide) -> int:
        stream_id = self._stream_id[side.value]
        if stream_id is None:
            raise FlowError(
                500,
                f"{'Client' if side is ProxySide.client else 'Server'} stream_id not set.",
            )
        return stream_id

    def wait_for_all_connections_closed(self) -> Coroutine[None]:
        return asyncio.wait(
            {
                self.wait_for_connection_closed(ProxySide.client),
                self.wait_for_connection_closed(ProxySide.server),
            },
            return_when=asyncio.ALL_COMPLETED,
        )

    def wait_for_all_streams_ended(self) -> Coroutine[None]:
        return asyncio.wait(
            {
                self.wait_for_stream_ended(ProxySide.client),
                self.wait_for_stream_ended(ProxySide.server),
            },
            return_when=asyncio.ALL_COMPLETED,
        )

    def wait_for_any_connection_closed(self) -> Coroutine[None]:
        return asyncio.wait(
            {
                self.wait_for_connection_closed(ProxySide.client),
                self.wait_for_connection_closed(ProxySide.server),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )

    def wait_for_any_stream_ended(self) -> Coroutine[None]:
        return asyncio.wait(
            {
                self.wait_for_stream_ended(ProxySide.client),
                self.wait_for_stream_ended(ProxySide.server),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )

    def wait_for_connection_closed(self, side: ProxySide) -> Coroutine[None]:
        return self.proto(side).wait_closed()

    def wait_for_stream_ended(self, side: ProxySide) -> Coroutine[None]:
        return self._stream_ended[side.value].wait()


class RawBridge(Bridge):
    def __init__(
        self,
        *,
        client: IncomingProtocol,
        client_stream_id: int,
        server: OutgoingProtocol,
        server_stream_id: int,
    ) -> None:
        super().__init__((client, server), (client_stream_id, server_stream_id))
        self._data_frames: Deque[Tuple[bytes, ProxySide]] = collections.deque()
        self._data_ready: asyncio.Event = asyncio.Event()

    def post_data(self, from_side: ProxySide, data: bytes) -> None:
        self._data_frames.append((data, from_side))
        self._data_ready.set()

    async def run(self) -> None:
        flow = tcp.TCPFlow(self.client, self.server, True)
        try:
            while True:
                # pump all messages
                # NOTE: This is done at the beginning on purpose, to raise an error
                #       if there are any pending messages for a closed connection.
                while self._data_frames:
                    data, from_side = self._data_frames.popleft()
                    tcp_message = tcp.TCPMessage(from_side is ProxySide.client, data)
                    flow.messages.append(tcp_message)
                    await self.context.ask("tcp_message", flow)
                    self.send(from_side.other_side, tcp_message.content)
                self._data_ready.clear()

                # check if both connections and at least one stream is still alive
                if self.have_all_streams_ended():
                    break
                if self.is_any_connection_closed():
                    raise FlowError(502, "Connection closed before ending stream.")

                # wait for more
                await asyncio.wait(
                    {
                        self.wait_for_any_connection_closed(),
                        self.wait_for_all_streams_ended(),
                        self._data_ready.wait(),
                    },
                    return_when=asyncio.FIRST_COMPLETED,
                )
        except FlowError as exc:
            flow.error = baseflow.Error(exc.message)
            self.context.tell("tcp_error", flow)
        finally:
            flow.live = False
            self.context.tell("tcp_end", flow)

    def send(self, to_side: ProxySide, data: bytes) -> None:
        super().send(
            to_side,
            lambda proto, stream_id: proto._quic.send_stream_data(
                stream_id=stream_id, data=data,
            ),
            self.has_stream_ended(to_side.other_side),
        )


class HttpBridge(Bridge):
    def __init__(
        self,
        *,
        client: IncomingProtocol,
        server: Optional[OutgoingProtocol],
        stream_id: int,
        headers: Headers,
        push_id: Optional[int] = None,
        push_promise_to: Optional[HttpBridge] = None,
    ) -> None:
        if (push_id is None) ^ (push_promise_to is None):
            raise ValueError(
                "push_id and push_promise_to must either both be set or both be None"
            )

        super().__init__((client, server), (stream_id, None))
        self._flow: http.HTTPFlow = http.HTTPFlow(
            client, server, True, self.context.mode.name
        )
        self._is_push: bool = push_id is not None
        if self._is_push:
            self._flow.metadata["h2-pushed-stream"] = True
        self._push_id: Optional[int] = push_id
        self._push_bridge: Optional[HttpBridge] = push_promise_to
        self._headers: Headers = headers
        self._origin: ProxySide = ProxySide.server if self._is_push else ProxySide.client
        self._data_frames: Deque[Tuple[True, bytes, ProxySide]] = collections.deque()
        self._data_ready: asyncio.Event = asyncio.Event()
        self._ws_flow: websocket.WebSocketFlow
        self._ws_connections: Tuple[wsproto.Connection, wsproto.Connection]
        self._ws_buffers: Tuple[List[Union[bytes, str]], List[Union[bytes, str]]]

    def post_data(
        self, from_side: ProxySide, data: bytes, is_header: bool = False
    ) -> None:
        self._data_frames.append((is_header, data, from_side))
        self._data_ready.set()

    def _build_headers_from_flow_request(self) -> Headers:
        headers: Headers = list()

        def add_pseudo_header(
            header: KnownPseudoHeaders, value: Optional[bytes]
        ) -> None:
            if value is not None:
                headers.append((b":" + header.name.encode(), value))

        # add all known pseudo headers
        add_pseudo_header(KnownPseudoHeaders.method, self._flow.request.method)
        add_pseudo_header(KnownPseudoHeaders.scheme, self._flow.request.scheme)
        add_pseudo_header(KnownPseudoHeaders.authority, self._flow.request.host_header)
        add_pseudo_header(KnownPseudoHeaders.path, self._flow.request.path)
        if self._flow.request.metadata.get("websocket", False):
            add_pseudo_header(KnownPseudoHeaders.protocol, b"websocket")

        # add all but the host header
        for header, value in self._flow.request.headers:
            header = header.lower()
            if header != b"host":
                headers.append((header, value))
        return headers

    def _build_flow_request_from_headers(self) -> http.HTTPRequest:
        known_pseudo_headers: Dict[bytes, KnownPseudoHeaders] = {
            b":" + x.name.encode(): x for x in KnownPseudoHeaders
        }
        pseudo_headers: Dict[KnownPseudoHeaders, bytes] = {}
        headers: List[Tuple[bytes, bytes]] = []
        host_header: bytes = None
        first_line_format: str
        method: bytes
        scheme: bytes
        host: Union[bytes, str]
        port: int
        path: bytes

        # helper function
        def require(header: KnownPseudoHeaders) -> bytes:
            value = pseudo_headers.get(header)
            if value is None:
                raise ProtocolError(f"Pseudo header :{header.name} is missing.")
            return value

        # filter out known headers (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.3)
        for header, value in self._headers:
            if self._is_pseudo_header(header):
                pseudo_header = known_pseudo_headers.get(header)
                if pseudo_header is None:
                    raise ProtocolError(
                        f"Pseudo header '{header.decode()}' is unknown."
                    )
                if pseudo_header in pseudo_headers:
                    raise ProtocolError(
                        f"Pseudo header :{pseudo_header.name} must occur only once."
                    )
                pseudo_headers[pseudo_header] = value
            else:
                if header == b"host":
                    if host_header is not None:
                        raise ProtocolError("Host header must occur only once.")
                    host_header = value
                headers.append((header, value))

        # clients could use host instead of :authority (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1)
        if KnownPseudoHeaders.authority in pseudo_headers:
            authority = pseudo_headers[KnownPseudoHeaders.authority]
            if host_header is not None:
                if host_header != authority:
                    raise ProtocolError(
                        f"Host header '{host_header.decode()}' differs from :authority '{authority.decode()}'."
                    )
                self.log(
                    LogLevel.info, "Host header and :authority set, but same value."
                )
            else:
                host_header = authority
                headers.append((b"host", host_header))

        # get scheme, path and first_line_format, handle CONNECT requests differently
        method = require(KnownPseudoHeaders.method)
        if method.upper() == b"CONNECT":
            protocol = pseudo_headers.get(KnownPseudoHeaders.protocol)
            if protocol is None:
                # ordinary CONNECT (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.2 -> https://tools.ietf.org/html/rfc7540#section-8.3)
                if (
                    KnownPseudoHeaders.scheme in pseudo_headers
                    or KnownPseudoHeaders.path in pseudo_headers
                ):
                    raise ProtocolError(
                        "CONNECT method doesn't allow :scheme and :path headers."
                    )
                if host_header is None:
                    raise ProtocolError(
                        "CONNECT method requires :authority or host header."
                    )
                scheme = None
                path = None
                first_line_format = "authority"
            else:
                # extended CONNECT (https://tools.ietf.org/html/draft-ietf-httpbis-h2-websockets-07#section-4)
                if protocol.lower() != b"websocket":
                    raise ProtocolError(
                        f"Only 'websocket' is supported for :protocol header, got '{protocol.decode()}'."
                    )
                self._flow.metadata["websocket"] = True
                scheme = require(KnownPseudoHeaders.scheme)
                if scheme.lower() not in [b"http", b"https"]:
                    raise ProtocolError(
                        f"Only 'http' and 'https' are supported for :scheme during a websocket CONNECT, got '{scheme.decode()}'."
                    )
                path = require(KnownPseudoHeaders.path)
                first_line_format = "absolute"
        else:
            # ordinary request (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1)
            scheme = require(KnownPseudoHeaders.scheme)
            path = require(KnownPseudoHeaders.path)
            first_line_format = "relative" if host_header is None else "absolute"

        # check any given path (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1)
        if path is not None and path != b"*" and not path.startswith(b"/"):
            raise ProtocolError(
                "The value of the :path must either be in asterisk or relative form."
            )

        # get the host and port, depending on the mode of operation
        if self.context.mode is ProxyMode.regular:
            # check if a target was given
            if host_header is None:
                # this is very likely to happen on pushes, correct for that
                if self._is_push:
                    host_header = self._push_bridge.request.host_header
                    if host_header is None:
                        raise FlowError(
                            400,
                            "Could not get host header for server push from original request.",
                        )
                    first_line_format = "absolute"
                    headers.append((b"host", host_header))
                else:
                    raise FlowError(
                        400,
                        "Request to regular proxy requires :authority or host header.",
                    )
            # check for userinfo https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1
            parts = host_header.split(b"@")
            if (
                len(parts) > 1
                and scheme is not None
                and scheme.lower() not in [b"http", b"https"]
            ):
                ProtocolError(
                    "The :authority or host header contains userinfo."
                )  # don't log
            # get host and port
            parts = parts[-1].split(b":")
            if len(parts) > 2:
                ProtocolError(
                    f"The :authority or host header '{host_header.decode()}' is malformed."
                )
            host = parts[0]
            if len(parts) > 1:
                try:
                    port = int(parts[1])
                    if port < 0 or port > 65535:
                        raise ValueError
                except ValueError:
                    ProtocolError(
                        f"The port in the :authority or host header '{host_header.decode()}' is invalid."
                    )
            elif scheme is None:
                # can only happen in ordinary CONNECT
                raise ProtocolError(
                    f"CONNECT method requires port in :authority or host header, got '{host_header.decode()}'."
                )
            elif scheme.lower() == b"http":
                port = 80
            elif scheme.lower() == b"https":
                port = 443
            else:
                raise FlowError(
                    501,
                    f"Regular proxy only supports 'http' and 'https' :scheme, got '{scheme.decode()}'.",
                )
        elif (
            self.context.mode is ProxyMode.upstream
            or self.context.mode is ProxyMode.reverse
        ):
            host, port = self.context.upstream_or_reverse_address
        elif self.context.mode is ProxyMode.transparent:
            host, port = self.client.server
        else:
            raise NotImplementedError

        # create the request object and return the flow
        return http.HTTPRequest(
            first_line_format,
            method,
            scheme,
            host,
            port,
            path,
            b"HTTP/0.9"
            if isinstance(self.proto(self._origin)._http, H0Connection)
            else b"HTTP/3",
            headers,
            None,
            timestamp_start=time.time(),
            timestamp_end=None,
        )

    def _handle_flow_error(self, exc: FlowError) -> None:
        # log the error
        self.log(LogLevel.warn, exc.message)

        # try to send the status
        if not self.is_connection_closed(self._origin) and not self.has_sent_end_stream(
            self._origin
        ):
            try:
                self.send(
                    self._origin,
                    headers=[
                        (b":status", str(exc.status).encode()),
                        (b"server", SERVER_NAME.encode()),
                        (b"date", formatdate(time.time(), usegmt=True).encode()),
                    ],
                    end_stream=True,
                )
            except FrameUnexpected:
                pass
            else:
                self.client.transmit()

    def _handle_protocol_error(self, exc: ProtocolError) -> None:
        # close the connection (will be logged when ConnectionTerminated is handled)
        self.client.close(error_code=exc.error_code, reason_phrase=exc.reason_phrase)

    async def _handle_websocket_close_connection(
        self, from_side: ProxySide, event: wsproto.events.CloseConnection
    ) -> None:
        # set the flow properties
        self._ws_flow.close_sender = from_side.name
        self._ws_flow.close_code = event.code
        self._ws_flow.close_reason = event.reason

        # forward the close and respond to the message
        self.send(
            from_side.other_side,
            data=self._ws_connections[from_side.other_side.value].send(
                wsproto.events.CloseConnection(code=event.code, reason=event.reason)
            ),
            end_stream=True,
        )
        self.send(
            from_side,
            data=self._ws_connections[from_side.value].send(event.response()),
            end_stream=True,
        )

    async def _handle_websocket_message(
        self, from_side: ProxySide, event: wsproto.events.Message
    ) -> None:
        # copied from mitmproxy
        fb = self._ws_buffers[from_side.value]
        fb.append(event.data)

        if event.message_finished:
            original_chunk_sizes = [len(f) for f in fb]

            if isinstance(event, wsproto.events.TextMessage):
                message_type = wsproto.frame_protocol.Opcode.TEXT
                payload = "".join(fb)
            else:
                message_type = wsproto.frame_protocol.Opcode.BINARY
                payload = b"".join(fb)

            fb.clear()

            websocket_message = websocket.WebSocketMessage(
                message_type, from_side is ProxySide.client, payload
            )
            length = len(websocket_message.content)
            self._ws_flow.messages.append(websocket_message)
            await self.context.ask("websocket_message", self._ws_flow)

            if not self._ws_flow.stream and not websocket_message.killed:

                def get_chunk(payload):
                    if len(payload) == length:
                        # message has the same length, we can reuse the same sizes
                        pos = 0
                        for s in original_chunk_sizes:
                            yield (
                                payload[pos : pos + s],
                                True if pos + s == length else False,
                            )
                            pos += s
                    else:
                        # just re-chunk everything into 4kB frames
                        # header len = 4 bytes without masking key and 8 bytes with masking key
                        chunk_size = 4092 if from_side is ProxySide.server else 4088
                        chunks = range(0, len(payload), chunk_size)
                        for i in chunks:
                            yield (
                                payload[i : i + chunk_size],
                                True if i + chunk_size >= len(payload) else False,
                            )

                for chunk, final in get_chunk(websocket_message.content):
                    self.send(
                        from_side.other_side,
                        data=self._ws_connections[from_side.other_side.value].send(
                            wsproto.events.Message(data=chunk, message_finished=final)
                        ),
                    )

        if self._ws_flow.stream:
            self.send(
                from_side.other_side,
                data=self._ws_connections[from_side.other_side.value].send(
                    wsproto.events.Message(
                        data=event.data, message_finished=event.message_finished
                    )
                ),
            )

    def _is_pseudo_header(self, header: Optional[bytes]) -> bool:
        if header is None:
            raise ProtocolError("Empty header name is not allowed.")
        if header != header.lower():
            raise ProtocolError(
                f"Uppercase header name '{header.decode()}' is not allowed."
            )
        return header.startswith(b":")

    def _update_request_headers(
        self, request: http.HTTPRequest, headers: Headers
    ) -> None:
        # only allow non-pseudo headers (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1)
        for header, value in headers:
            if self._is_pseudo_header(header):
                raise ProtocolError(
                    f"Pseudo header '{header.decode()}' not allowed in trailers."
                )
            request.headers.add(header, value)

    async def _pump_websocket_data(self) -> bool:
        # pump all messages
        while self._data_frames:
            is_header, data, from_side = self._data_frames.popleft()
            if is_header:
                raise FlowError(
                    502, f"Headers received in websocket flow from {from_side.name}."
                )
            ws = self._ws_connections[from_side.value]
            ws.receive_data(data)
            for event in ws.events():
                if isinstance(event, wsproto.events.Message):
                    await self._handle_websocket_message(from_side, event)
                elif isinstance(event, wsproto.events.CloseConnection):
                    await self._handle_websocket_close_connection(from_side, event)
                    return False
                else:
                    self.log(
                        LogLevel.debug,
                        f"Unknown websocket event '{type(event).__name__}' received from {from_side.name}.",
                    )
        self._data_ready.clear()
        return True

    async def _read_request_data(self) -> bytes:
        pass

    async def _wait_for_websocket_data(self) -> None:
        # check if both connections and at least one stream is still alive
        if self.have_all_streams_ended():
            raise FlowError(502, "Streams have been closed before ending websocket.")
        if self.is_any_connection_closed():
            raise FlowError(502, "Connection closed before ending websocket.")

        # wait for more
        await asyncio.wait(
            {
                self.wait_for_any_connection_closed(),
                self.wait_for_all_streams_ended(),
                self._data_ready.wait(),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )

    async def run(self) -> None:
        try:
            # parse the headers and allow patching
            self._flow.request = self._build_flow_request_from_headers()
            await self.context.ask("requestheaders", self._flow)

            # handle pushes differentyl
            if self._is_push:
                # send the push
                Bridge.send(
                    self._push_bridge,
                    ProxySide.client,
                    lambda proto, stream_id: proto._http.send_push_promise(
                        stream_id=stream_id,
                        headers=self._build_headers_from_flow_request(),
                    ),
                )

            else:
                # CONNECT is only allowed for websockets
                is_websocket: bool = self._flow.metadata.get("websocket", False)
                if self._flow.request.method == "CONNECT" and not is_websocket:
                    raise FlowError(501, "CONNECT for QUIC not implemented.")

                # there is nothing in the RFC against it, but that leaves us with trailers
                if (
                    self._flow.request.headers.get("expect", "").lower()
                    == "100-continue"
                ):
                    self.send(self._origin, headers=[(b":status", b"100")])
                    self._flow.request.headers.pop("expect")

                # update host header in reverse proxy mode
                if (
                    self.context.mode is ProxyMode.reverse
                    and not self.context.options.keep_host_header
                ):
                    self._flow.request.host_header = (
                        self.context.upstream_or_reverse_address[0]
                        + b":"
                        + str(self.context.upstream_or_reverse_address[1]).encode()
                    )

            # handle different content scenarios
            if is_websocket or self._flow.request.stream:
                self._flow.request.data.content = None
            else:
                self._flow.request.data.content = await self._read_request_data()

            # request is done, log it
            self._flow.request.timestamp_end = time.time()
            self.log(
                LogLevel.debug,
                None,
                {
                    "request": repr(self._flow.request),
                    "push": self._is_push,
                    "websocket": is_websocket,
                    "origin": self._origin.name,
                },
            )

            # allow pre-recorded reponses
            await self.context.ask("request", self._flow)
            if is_websocket:
                await self.context.ask("websocket_handshake", self._flow)

        except FlowError as exc:
            self._handle_flow_error(exc)
            self._flow.error = baseflow.Error(exc.message)
            await self.context.ask("error", self._flow)
        except ProtocolError as exc:
            self._handle_protocol_error(exc)
            self._flow.error = baseflow.Error(exc.reason_phrase)
            await self.context.ask("error", self._flow)
        finally:
            self._flow.live = False

    async def run_push(self) -> None:
        # set flag and allow patching
        self._flow.metadata["h2-pushed-stream"] = True
        await self.context.ask("requestheaders", self._flow)

    async def run_websocket(self) -> None:
        # handle the websocket flow after negotiation
        self._ws_flow = websocket.WebSocketFlow(self.client, self.server, self._flow)
        self._ws_flow.metadata["websocket_handshake"] = self._flow.id
        self._flow.metadata["websocket_flow"] = self._ws_flow.id
        await self.context.ask("websocket_start", self._ws_flow)
        try:
            self._ws_connections = (
                wsproto.Connection(wsproto.ConnectionType.SERVER),
                wsproto.Connection(wsproto.ConnectionType.CLIENT),
            )
            self._ws_buffers = (list(), list())
            while await self._pump_websocket_data():
                await self._wait_for_websocket_data()
        except FlowError as exc:
            self._handle_flow_error(exc)
            self._ws_flow.error = baseflow.Error(exc.message)
            await self.context.tell("websocket_error", self._ws_flow)
        except ProtocolError as exc:
            self._handle_protocol_error(exc)
            self._ws_flow.error = baseflow.Error(exc.reason_phrase)
            await self.context.tell("websocket_error", self._ws_flow)
        finally:
            self._flow.live = False
            self.context.tell("websocket_end", self._ws_flow)

    def send(
        self,
        to_side: ProxySide,
        headers: Optional[Headers] = None,
        data: Optional[bytes] = None,
        end_stream: bool = False,
    ) -> None:
        def internal_send(proto: ConnectionProtocol, stream_id: int) -> None:
            if headers is not None:
                proto._http.send_headers(stream_id, headers)
            if data is not None:
                proto._http.send_data(stream_id, data)

        super().send(to_side, internal_send, end_stream)


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def quicServer(config: proxy.ProxyConfig, channel: controller.Channel) -> Coroutine:
    # prepare all necessary fields for the configuration
    ticket_store = SessionTicketStore()
    context = ProxyContext(config, channel)
    hostname = socket.gethostname().encode("idna")
    certificate, certificate_chain, private_key = context.generate_certificate(
        hostname, {b"localhost", b"::1", b"127.0.0.1", hostname}, b"mitmproxy/quic"
    )

    # start serving
    return serve(
        context.options.listen_host or "::",
        context.options.listen_port,
        configuration=QuicConfiguration(
            alpn_protocols=H3_ALPN + H0_ALPN
            if context.mode is ProxyMode.regular
            else None,
            is_client=False,
            is_transparent=context.mode is ProxyMode.transparent,
            secrets_log_file=log_master_secret,
            certificate=certificate,
            certificate_chain=certificate_chain,
            private_key=private_key,
        ),
        create_protocol=functools.partial(IncomingProtocol, context),
        session_ticket_fetcher=ticket_store.pop,
        session_ticket_handler=ticket_store.add,
    )
