from __future__ import annotations
import asyncio
import collections
import enum
import functools
import ipaddress
import socket
import ssl
import sys
import time
import traceback
from email.utils import formatdate
from typing import (
    Any,
    AsyncIterable,
    cast,
    Callable,
    Deque,
    Dict,
    List,
    Tuple,
    Optional,
    Set,
    Type,
    Union,
)

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
from mitmproxy.net.http.status_codes import RESPONSES
from mitmproxy.net.quic import transparent_serve
from mitmproxy.utils.strutils import bytes_to_escaped_str

import OpenSSL
import re
import wsproto

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    rsa,
)
from cryptography.hazmat.primitives.serialization import Encoding

from ..net.tls import log_master_secret
from ..version import VERSION


from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.buffer import Buffer
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
from aioquic.quic.connection import (
    QuicConnection,
    stream_is_client_initiated,
    stream_is_unidirectional,
)
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)
from aioquic.quic.packet import QuicErrorCode
from aioquic.tls import (
    CipherSuite,
    ClientHello,
    Context as TlsContext,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
    pull_client_hello,
    pull_server_hello,
)

PARSE_HOST_HEADER = re.compile(r"^(?P<host>[^:]+|\[.+\])(?::(?P<port>\d+))?$")
SERVER_NAME = "mitmproxy/" + VERSION

HttpConnection = Union[H0Connection, H3Connection]


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


class RequestPseudoHeaders(enum.Enum):
    method = 1
    scheme = 2
    authority = 3
    path = 4
    protocol = 5


class ResponsePseudoHeaders(enum.Enum):
    status = 1


PseudoHeaders = Union[RequestPseudoHeaders, ResponsePseudoHeaders]


class FlowError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ProxyContext:
    def __init__(self, config: proxy.ProxyConfig, channel: controller.Channel) -> None:
        self.upstream_or_reverse_address: Tuple[str, int]
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
            self.upstream_or_reverse_address = (host.decode("idna"), port)
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
            g = m.reply.q.get()
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
        additional: Optional[Dict[str, Any]] = None,
    ) -> None:
        msg = f"[QUIC-{type}] {from_addr[0]}:{from_addr[1]} -> {to_addr[0]}:{to_addr[1]}: {msg}"
        if additional is not None:
            msg = ("\n" + " " * 6).join(
                [msg] + [f"{name}: {value}" for (name, value) in additional.items()]
            )
        self.tell("log", log.LogEntry(msg, level.name))

    def tell(self, mtype, m):
        if not self._channel.should_exit.is_set():
            m.reply = controller.DummyReply()
            if asyncio.get_event_loop() is self._channel.loop:
                asyncio.ensure_future(
                    self._channel.master.addons.handle_lifecycle(mtype, m)
                )
            else:
                asyncio.run_coroutine_threadsafe(
                    self._channel.master.addons.handle_lifecycle(mtype, m),
                    self._channel.loop,
                )


def handle_except(loggable: Any) -> None:
    exc_type, exc, tb = sys.exc_info()
    try:
        loggable.log(
            LogLevel.error,
            "Unhandled exception.",
            {
                "type": exc_type.__name__,
                "message": str(exc),
                "stacktrace": "\n" + "".join(traceback.format_tb(tb)),
            },
        )
    except:
        traceback.print_tb(tb, file=sys.stderr)


class ConnectionProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        client: IncomingProtocol,
        server: Optional[OutgoingProtocol],
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._side: ProxySide
        self._push_bridges: Dict[int, PushBridge] = {}
        self._bridges: Dict[int, Bridge] = {}
        self._http: Optional[HttpConnection] = None
        self._is_closed: bool = False
        self._local_close: bool = False
        self._client: IncomingProtocol = client
        self._server: Optional[OutgoingProtocol] = server

        # patch QuicConnection._initialize
        orig_initialize = self._quic._initialize

        def initialize_replacement(*args, **kwargs):
            try:
                return orig_initialize(*args, **kwargs)
            finally:
                self.patch_tls(self._quic.tls)

        self._quic._initialize = initialize_replacement

        # determine the side
        if self is client:
            self._side = ProxySide.client
        elif self is server:
            self._side = ProxySide.server
        else:
            raise ValueError(
                "The current connection must either be the client or server connection."
            )

    def _handle_http_data_received(self, event: DataReceived) -> None:
        event_description = {
            "data_length": len(event.data),
            "stream_id": event.stream_id,
            "stream_ended": event.stream_ended,
        }
        if event.stream_id not in self._bridges:
            self.log(
                LogLevel.warn, "Data received on unknown stream.", event_description
            )
            return
        bridge = self._bridges[event.stream_id]
        bridge.post_data(self._side, event.data)

    def _handle_http_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            if event.push_id is None:
                self._handle_http_headers_received(event)
            else:
                self._handle_http_push_headers_or_data_received(event)
        elif isinstance(event, DataReceived):
            if event.push_id is None:
                self._handle_http_data_received(event)
            else:
                self._handle_http_push_headers_or_data_received(event)
        elif isinstance(event, PushPromiseReceived):
            self._handle_http_push_promise_received(event)
        else:
            self.log(
                LogLevel.warn,
                "Unknown H3Event received",
                {"type": type(event).__name__},
            )

    def _handle_http_headers_received(self, event: HeadersReceived) -> None:
        event_description = {
            "header_length": len(event.headers),
            "stream_id": event.stream_id,
            "stream_ended": event.stream_ended,
        }
        if event.stream_id not in self._bridges:
            # only the client can initiate a new stream
            if self._side is ProxySide.server:
                self.log(
                    LogLevel.warn,
                    "Received headers for unknown stream.",
                    event_description,
                )
                return

            self._bridges[event.stream_id] = RequestBridge(
                client=self._client,
                server=self._server,
                stream_id=event.stream_id,
                headers=event.headers,
            )
        else:
            bridge = self._bridges[event.stream_id]
            bridge.post_data(self._side, event.headers, is_header=True)

    def _handle_http_push_headers_or_data_received(
        self, event: Union[HeadersReceived, DataReceived]
    ) -> None:
        is_data = isinstance(event, DataReceived)
        event_description = {
            "type": "data" if is_data else "trailers",
            "stream_id": event.stream_id,
            "stream_ended": event.stream_ended,
            "push_id": event.push_id,
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
        if bridge.has_stream_id(self._side):
            bridge_stream_id = bridge.stream_id(self._side)
            if bridge_stream_id != event.stream_id:
                self.log(
                    LogLevel.warn,
                    "Push data received on different stream.",
                    event_description + {"push_stream_id": bridge_stream_id},
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
            bridge.set_stream_id(self._side, event.stream_id)
            self._bridges[event.stream_id] = bridge  # necessary for stream end/reset
        bridge.post_data(
            ProxySide.server,
            event.data if is_data else event.headers,
            is_header=not is_data,
        )

    def _handle_http_push_promise_received(self, event: PushPromiseReceived) -> None:
        event_description = {
            "headers_length": len(event.headers),
            "push_id": event.push_id,
            "stream_id": event.stream_id,
        }
        if self._side is ProxySide.client:
            # log and exit
            self.log(
                LogLevel.warn, "Push promise received from client.", event_description
            )
            return
        if event.stream_id not in self._bridges:
            # need a channel to forward the push
            self.log(
                LogLevel.warn,
                "Push promise received on unknown stream.",
                event_description,
            )
            return
        if event.push_id in self._push_bridges:
            # better drop it
            self.log(
                LogLevel.warn, "Duplicate push promise received.", event_description
            )
            return
        self._push_bridges[event.push_id] = PushBridge(
            client=self._client,
            server=self._server,
            headers=event.headers,
            push_id=event.push_id,
            push_promise_to=self._bridges[event.stream_id],
        )

    def _handle_raw_stream_data(self, event: StreamDataReceived) -> None:
        event_description = {
            "stream_id": event.stream_id,
            "data_length": len(event.data),
            "end_stream": event.end_stream,
        }
        # create or get the bridge and post the data
        bridge: RawBridge
        if event.stream_id not in self._bridges:
            # raw data can't be routed like a regular proxy request
            if not self._server:
                self.log(
                    LogLevel.warn,
                    "Received raw data without server connection.",
                    event_description,
                )
                return

            # only the client can initiate a new stream
            if self._side is ProxySide.server:
                self.log(
                    LogLevel.warn,
                    "Received raw data for unknown stream.",
                    event_description,
                )
                return

            # create the stream on the other side and register the bridge
            server_stream_id = self._server._quic.get_next_available_stream_id()
            bridge = RawBridge(
                client=self,
                client_stream_id=event.stream_id,
                server=self._server,
                server_stream_id=server_stream_id,
            )
            self._bridges[event.stream_id] = bridge
            self._server._bridges[server_stream_id] = bridge
        else:
            bridge = cast(RawBridge, self._bridges[event.stream_id])
        bridge.post_data(self._side, event.data)

    def _handle_stream_reset(self, event: StreamReset) -> None:
        # end the stream like an ordinary FIN would
        if event.stream_id not in self._bridges:
            self.log(
                LogLevel.debug,
                "Received reset for unknown stream.",
                {"stream_id": event.stream_id},
            )
            return
        bridge = self._bridges[event.stream_id]
        bridge.end_stream_cb(self._side, event.stream_id)

    @property
    def address(self) -> Tuple[str, int]:
        return self._quic._network_paths[0].addr[0:2]

    @address.setter
    def address(self, address: Tuple[str, int]) -> None:
        if address is not None:
            raise PermissionError

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
        return not self._is_closed

    def connection_terminated(self, event: ConnectionTerminated) -> None:
        # notify bridges
        self._is_closed = True
        for bridge in self._bridges.values():
            bridge.notify()
        for push_bridge in self._push_bridges.values():
            push_bridge.notify()

        # note the time and log the event
        self.timestamp_end = time.time()
        self.log(
            LogLevel.debug,
            "Connection closed.",
            {
                "error_code": event.error_code,
                "frame_type": event.frame_type,
                "reason_phrase": event.reason_phrase,
                "by_peer": not self._local_close,
            },
        )

    @property
    def context(self) -> ProxyContext:
        return self._client.context

    def establish_tls(self, *args, **kwargs):
        # there is no other way
        pass

    def finish(self) -> None:
        # for compatibility
        self.close()

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        # set the proper http connection
        if event.alpn_protocol.startswith("h3-"):
            self._http = H3Connection(self._quic)
        elif event.alpn_protocol.startswith("hq-"):
            self._http = H0Connection(self._quic)

        # store the security details
        self.alpn_proto_negotiated = event.alpn_protocol.encode("utf8")
        self.timestamp_tls_setup = time.time()
        self.tls_established = True
        self.tls_version = "TLSv1.3"

        # log a debug message
        self.log(
            LogLevel.debug,
            "TLS established.",
            {
                "alpn_protocol": event.alpn_protocol,
                "early_data_accepted": event.early_data_accepted,
                "session_resumed": event.session_resumed,
            },
        )

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        raise NotImplementedError

    def patch_tls(self, tls: TlsContext) -> None:
        pass

    def quic_event_received(self, event: QuicEvent) -> None:
        # handle known events
        if isinstance(event, HandshakeCompleted):
            self.handshake_complete(event)
        elif isinstance(event, ConnectionTerminated):
            self.connection_terminated(event)
        elif isinstance(event, StreamReset):
            self._handle_stream_reset(event)
        elif isinstance(event, StreamDataReceived):
            if self._http is None:
                self._handle_raw_stream_data(event)
            else:
                for http_event in self._http.handle_event(event):
                    self._handle_http_event(http_event)
            if event.end_stream and event.stream_id in self._bridges:
                self._bridges[event.stream_id].end_stream_cb(
                    self._side, event.stream_id
                )

    def send(self, *args, **kwargs) -> None:
        self.log(LogLevel.debug, "Sending not supported on connection level.")


class OutgoingProtocol(ConnectionProtocol, connections.ServerConnection):
    def __init__(self, client: IncomingProtocol, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, client, self, *args, **kwargs)
        connections.ServerConnection.__init__(self, None, None, None)
        # store the used SNI
        if self._quic.configuration.server_name is not None:
            self.sni = self._quic.configuration.server_name.encode("idna")

    def create_stream_id(self, bridge: Bridge) -> int:
        assert bridge is not None
        stream_id = self._quic.get_next_available_stream_id()
        self._bridges[stream_id] = bridge
        bridge.set_stream_id(self._side, stream_id)
        return stream_id

    def datagram_received(self, *args, **kwargs) -> None:
        # protect the main entry point
        try:
            super().datagram_received(*args, **kwargs)
        except:
            handle_except(self)

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        self.context.log(
            "out", self.source_address, self.address, level, msg, additional
        )

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        super().handshake_complete(event)
        self.cert = self.context.convert_certificate(self._quic.tls._peer_certificate)
        self.server_certs = [
            self.context.convert_certificate(cert)
            for cert in self._quic.tls._peer_certificate_chain
        ]

    def patch_tls(self, tls: TlsContext) -> None:
        # hook the client hello to get the cipher name
        orig_client_handle_hello = tls._client_handle_hello

        def client_handle_hello_replacement(input_buf: Buffer, *args, **kwargs) -> Any:
            pos = input_buf.tell()
            server_hello = pull_server_hello(input_buf)
            input_buf.seek(pos)
            self.cipher_name = CipherSuite(server_hello.cipher_suite).name
            return orig_client_handle_hello(input_buf, *args, **kwargs)

        tls._client_handle_hello = client_handle_hello_replacement

    @property
    def source_address(self) -> Tuple[str, int]:
        return self._transport.get_extra_info("sockname")[0:2]

    @source_address.setter
    def source_address(self, source_address: Tuple[str, int]) -> None:
        if source_address is not None:
            raise PermissionError


class IncomingProtocol(ConnectionProtocol, connections.ClientConnection):
    def __init__(self, context: ProxyContext, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, self, None, *args, **kwargs)
        connections.ClientConnection.__init__(self, None, None, None)
        self._context: ProxyContext = context
        self._servers: Dict[Tuple[str, int], OutgoingProtocol] = {}

    def _handle_client_hello(self, tls: TlsContext, hello: ClientHello) -> None:
        host: bytes = None
        sans: Set = set()
        organization: Optional[str] = None
        extra_chain: Optional[List[certs.Cert]] = None

        # store the sni
        self.sni = (
            None if hello.server_name is None else hello.server_name.encode("idna")
        )

        # create the outgoing connection if possible
        # NOTE: This is a deviation from mitmproxy's default behavior. Mitmproxy only initiates a connection
        #       if it is necessary, e.g. if `upstream_cert` is set. Otherwise it allows to replay an entire
        #       flow. However, in order to allow the inspection of any stream data, this would require
        #       something like `ask("alpn_protocol", flow)` to also record and replay the selected protocol.
        if self.context.mode is not ProxyMode.regular:
            self._server = asyncio.run_coroutine_threadsafe(
                self.create_outgoing_protocol(
                    remote_addr=self.server
                    if self.context.mode is ProxyMode.transparent
                    else self.context.upstream_or_reverse_address,
                    sni=hello.server_name,
                    alpn_protocols=hello.alpn_protocols,
                ),
                self._loop,
            ).result()
            tls.alpn_negotiated = self._server.alpn_proto_negotiated.decode("utf8")

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
            upstream_or_reverse_host = self.context.upstream_or_reverse_address[
                0
            ].encode("idna")
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
        # just as in `datagram_received`, but with the async result of `_quic.receive_datagram`
        try:
            future.result()
            self._process_events()
            self.transmit()
        except:
            handle_except(self)

    def connection_terminated(self, event: ConnectionTerminated) -> None:
        super().connection_terminated(event)
        # close the server connections as well
        for server in self._servers.values():
            server.close(
                error_code=event.error_code,
                frame_type=event.frame_type,
                reason_phrase=event.reason_phrase,
            )

    @property
    def context(self) -> ProxyContext:
        return self._context

    async def create_outgoing_protocol(
        self,
        *,
        remote_addr=Tuple[str, int],
        sni: Optional[str],
        alpn_protocols: List[str],
    ) -> OutgoingProtocol:
        # ensure the connection is open and return any existing connection
        if not self.connected():
            raise FlowError(502, "Connection already terminated.")
        if remote_addr in self._servers:
            return self._servers[remote_addr]

        # create a new one
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

        # spoofing is not yet supported, but un-map IPv4 addresses
        if self.context.options.spoof_source_address:
            self.log(LogLevel.info, "Source address spoofing not yet supported.")
        addr = ipaddress.ip_address(remote_addr[0])
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
            remote_addr = (str(addr), remote_addr[1])
        _, protocol = await self._loop.create_datagram_endpoint(
            functools.partial(OutgoingProtocol, self, connection),
            local_addr=("::" if addr.version == 6 else "0.0.0.0", 0),
        )

        # recheck (there was an await in between)
        if not self.connected():
            raise FlowError(502, "Connection already terminated.")
        if remote_addr in self._servers:
            return self._servers[remote_addr]

        # add and connect the server
        protocol = cast(OutgoingProtocol, protocol)
        self._servers[remote_addr] = protocol
        protocol.connect(remote_addr)
        await protocol.wait_connected()
        return protocol

    def datagram_received(self, data: bytes, addr: Tuple) -> None:
        try:
            if self.tls_established:
                self._quic.receive_datagram(cast(bytes, data), addr, self._loop.time())
                self._process_events()
                self.transmit()
            else:
                # everything before the handshake must happen in a different thread
                # to support blocking for the client, since QuicConnection is not async
                self._loop.run_in_executor(
                    None,
                    self._quic.receive_datagram,
                    bytes(data),
                    addr,
                    self._loop.time(),
                ).add_done_callback(self._process_events_and_transmit)
        except:
            handle_except(self)

    def handshake_complete(self, event: HandshakeCompleted) -> None:
        super().handshake_complete(event)
        self.mitmcert = self.context.convert_certificate(self._quic.tls.certificate)

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        self.context.log("in", self.address, self.server, level, msg, additional)

    def patch_tls(self, tls: TlsContext) -> None:
        # hook the server hello to set the certificate and get the cipher name
        orig_server_handle_hello = tls._server_handle_hello

        def server_handle_hello_replacement(input_buf: Buffer, *args, **kwargs) -> Any:
            pos = input_buf.tell()
            client_hello = pull_client_hello(input_buf)
            input_buf.seek(pos)
            self._handle_client_hello(tls, client_hello)
            if client_hello.cipher_suites is not None:
                for c in tls._cipher_suites:
                    if c in client_hello.cipher_suites:
                        self.cipher_name = c.name
                        break
            return orig_server_handle_hello(input_buf, *args, **kwargs)

        tls._server_handle_hello = server_handle_hello_replacement

    @property
    def server(self) -> Tuple[str, int]:
        return self._transport.get_extra_info("sockname")[0:2]

    @server.setter
    def server(self, server: Tuple[str, int]) -> None:
        if server is not None:
            raise PermissionError


class Bridge:
    def __init__(
        self,
        protos: Tuple[IncomingProtocol, Optional[OutgoingProtocol]],
        stream_ids: Tuple[Optional[int], Optional[int]],
    ) -> None:
        assert len(protos) == 2 and len(stream_ids) == 2
        assert protos[ProxySide.client] is not None
        assert not any(
            [
                proto is None and id is not None
                for (proto, id) in zip(protos, stream_ids)
            ]
        )
        self._proto: List[Optional[ConnectionProtocol]] = list(protos)
        self._stream_id: List[Optional[int]] = list(stream_ids)
        self._stream_ended_received: List[bool] = [False, False]
        self._end_stream_sent: List[bool] = [False, False]
        self._event: asyncio.Event = asyncio.Event()
        asyncio.ensure_future(self._internal_run())

    async def _internal_run(self) -> None:
        try:
            try:
                await self.run()
            finally:
                # ensure the streams have been ended
                for side in ProxySide:
                    if self.can_send[side]:
                        # TODO: replace with sending RESET_STREAM once aioquic supports it
                        try:
                            proto = self._proto[side]
                            proto._quic.send_stream_data(
                                stream_id=self._stream_id[side],
                                data=b"",
                                end_stream=True,
                            )
                            proto.transmit()
                        except:
                            handle_except(self)
        except:
            handle_except(self)

    def _is_stream_writeable(self, stream_id: int, side: ProxySide) -> bool:
        # from QUIC protocol perspective, the server side acts like the client
        return stream_is_client_initiated(stream_id) == (
            side is ProxySide.server
        ) or not stream_is_unidirectional(stream_id)

    @property
    def can_receive(self) -> Tuple[bool, bool]:
        # used by bridges
        return tuple(
            [
                proto is not None
                and proto.connected()
                and stream_id is not None
                and not stream_ended
                for (proto, stream_id, stream_ended) in zip(
                    self._proto, self._stream_id, self._stream_ended_received
                )
            ]
        )

    @property
    def can_send(self) -> Tuple[bool, bool]:
        # used by bridges, same checks as in send method
        return tuple(
            [
                proto is not None
                and proto.connected()
                and stream_id is not None
                and self._is_stream_writeable(stream_id, side)
                and not end_stream
                for (proto, stream_id, side, end_stream) in zip(
                    self._proto, self._stream_id, ProxySide, self._end_stream_sent
                )
            ]
        )

    @property
    def client(self) -> IncomingProtocol:
        return cast(IncomingProtocol, self.proto(ProxySide.client))

    @property
    def context(self) -> ProxyContext:
        return self.client.context

    def end_stream_cb(self, side: ProxySide, stream_id: int) -> None:
        # called by the ConnectionProtocol when a stream_ended event was received
        assert stream_id is not None
        assert self._stream_id[side] == stream_id
        self._stream_ended_received[side] = True
        self.notify()

    @property
    def has_server(self) -> bool:
        return self._proto[ProxySide.server] is not None

    def has_stream_id(self, side: ProxySide) -> bool:
        return self._stream_id[side] is not None

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        description = {
            "is_push": isinstance(self, PushBridge),
            "has_server": self.has_server,
            "stream_id": self._stream_id,
            "stream_ended_received": self._stream_ended_received,
            "end_stream_sent": self._end_stream_sent,
        }
        if additional is not None:
            description.update(additional)
        self.context.log(
            "bridge",
            self.client.address,
            self.server.address if self.has_server else self.client.server,
            level,
            msg,
            description,
        )

    def notify(self) -> None:
        # called whenever a condition should be reevaluated
        self._event.set()

    def proto(self, side: ProxySide) -> ConnectionProtocol:
        proto = self._proto[side]
        if proto is None:
            raise FlowError(
                500, f"Protocol for {side.name} side not set.",
            )
        return proto

    async def run(self) -> None:
        pass

    def send(
        self,
        *,
        to_side: ProxySide,
        cb: Callable[[ConnectionProtocol, int], Optional[int]],
        end_stream: bool = False,
    ) -> Optional[int]:
        # ensure sending data is possible
        proto = self.proto(to_side)
        if not proto.connected():
            raise FlowError(
                500, f"Connection to {to_side.name} has already been closed.",
            )
        stream_id = self.stream_id(to_side)
        if not self._is_stream_writeable(stream_id, to_side):
            raise FlowError(
                500,
                f"Cannot send data on a {to_side.name}-initiated unidirectional stream.",
            )
        if self._end_stream_sent[to_side]:
            raise FlowError(
                500, f"Stream to {to_side.name} has already been ended by proxy.",
            )

        # send and transmit
        result = cb(proto, stream_id)
        if end_stream:
            proto._quic.send_stream_data(stream_id, b"", end_stream=True)
            self._end_stream_sent[to_side] = True
        proto.transmit()
        return result

    @property
    def server(self) -> OutgoingProtocol:
        return cast(OutgoingProtocol, self.proto(ProxySide.server))

    @server.setter
    def server(self, server: OutgoingProtocol) -> None:
        assert server is not None
        assert not self.has_server
        self._proto[ProxySide.server] = server
        self._flow.server_conn = server

    def set_stream_id(self, side: ProxySide, stream_id: int) -> None:
        # called from ConnectionProtocol for pushes and regular proxy bridges
        assert stream_id is not None
        assert self._proto[side] is not None
        assert self._stream_id[side] is None
        self._stream_id[side] = stream_id
        self.notify()

    def stream_id(self, side: ProxySide) -> int:
        stream_id = self._stream_id[side.value]
        if stream_id is None:
            raise FlowError(
                500, f"Stream id for {side.name} connection not set.",
            )
        return stream_id

    async def wait(self) -> None:
        await self._event.wait()
        self._event.clear()


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

    def post_data(self, from_side: ProxySide, data: bytes) -> None:
        self._data_frames.append((data, from_side))
        self.notify()

    async def run(self) -> None:
        flow = tcp.TCPFlow(self.client, self.server, True)
        flow.scheme = "https"
        await self.context.ask("tcp_start", flow)
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
                    self.send(to_side=from_side.other_side, data=tcp_message.content)

                # check if data can still be retrieved
                if not any(self.can_receive):
                    break

                # wait for more
                await self.wait()
        except FlowError as exc:
            flow.error = baseflow.Error(exc.message)
            self.context.tell("tcp_error", flow)
        finally:
            flow.live = False
            self.context.tell("tcp_end", flow)

    def send(self, to_side: ProxySide, data: bytes) -> None:
        super().send(
            to_side=to_side,
            cb=lambda proto, stream_id: proto._quic.send_stream_data(
                stream_id=stream_id, data=data,
            ),
            end_stream=self.can_receive[to_side.other_side],
        )


class HttpBridge(Bridge):
    def __init__(
        self,
        *,
        client: IncomingProtocol,
        server: Optional[OutgoingProtocol],
        stream_ids: Tuple[Optional[int], Optional[int]],
        headers: Headers,
    ) -> None:
        assert client is not None and headers is not None
        super().__init__((client, server), stream_ids)
        self._flow: http.HTTPFlow = http.HTTPFlow(
            client, server, True, self.context.mode.name
        )
        self._headers: Headers = headers
        self._data_frames: Tuple[
            Deque[Tuple[True, bytes]], Deque[Tuple[True, bytes]]
        ] = (collections.deque(), collections.deque())
        self._ws_flow: websocket.WebSocketFlow
        self._ws_connections: Tuple[wsproto.Connection, wsproto.Connection]
        self._ws_buffers: Tuple[List[Union[bytes, str]], List[Union[bytes, str]]]

    def _build_flow_request(self) -> http.HTTPRequest:
        host_header: bytes = None
        first_line_format: str
        method: bytes
        scheme: bytes
        host: str
        port: int
        path: bytes

        # initialize pseudo headers and ordinary ones
        pseudo_headers, headers = self._check_and_split_pseudo_headers(
            self._headers, RequestPseudoHeaders
        )
        for header, value in headers:
            if header == b"host":
                if host_header is not None:
                    raise ProtocolError("Host header must occur only once.")
                host_header = value

        # helper function
        def require(header: RequestPseudoHeaders) -> bytes:
            value = pseudo_headers.get(header)
            if value is None:
                raise ProtocolError(f"Pseudo header :{header.name} is missing.")
            return value

        # clients could use host instead of :authority
        # https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1
        if RequestPseudoHeaders.authority in pseudo_headers:
            authority = pseudo_headers[RequestPseudoHeaders.authority]
            if host_header is not None:
                if host_header != authority:
                    raise ProtocolError(
                        f"Host header '{bytes_to_escaped_str(host_header)}' differs from :authority '{bytes_to_escaped_str(authority)}'."
                    )
                self.log(
                    LogLevel.debug, "Host header and :authority set, but same value."
                )
            else:
                host_header = authority
                headers.append((b"host", host_header))

        # allow subclasses (read: pushes) to provide a host header
        if host_header is None:
            host_header = self.provide_host_header()
            if host_header is not None:
                headers.append((b"host", host_header))

        # get scheme, path and first_line_format, handle CONNECT requests differently
        method = require(RequestPseudoHeaders.method)
        if method.upper() == b"CONNECT":
            protocol = pseudo_headers.get(RequestPseudoHeaders.protocol)
            if protocol is None:
                # ordinary CONNECT
                # https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.2
                # https://tools.ietf.org/html/rfc7540#section-8.3
                if (
                    RequestPseudoHeaders.scheme in pseudo_headers
                    or RequestPseudoHeaders.path in pseudo_headers
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
                # extended CONNECT
                # https://tools.ietf.org/html/draft-ietf-httpbis-h2-websockets-07#section-4
                if protocol.lower() != b"websocket":
                    raise ProtocolError(
                        f"Only 'websocket' is supported for :protocol header, got '{bytes_to_escaped_str(protocol)}'."
                    )
                self._flow.metadata["websocket"] = True
                scheme = require(RequestPseudoHeaders.scheme)
                if scheme.lower() not in [b"http", b"https"]:
                    raise ProtocolError(
                        f"Websocket CONNECT only supports 'http' and 'https' for :scheme , got '{bytes_to_escaped_str(scheme)}'."
                    )
                path = require(RequestPseudoHeaders.path)
                first_line_format = "absolute"
        else:
            # ordinary request
            # https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1
            scheme = require(RequestPseudoHeaders.scheme)
            path = require(RequestPseudoHeaders.path)
            first_line_format = "relative" if host_header is None else "absolute"

        # check any given path
        # https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1
        if path is not None and path != b"*" and not path.startswith(b"/"):
            raise ProtocolError(
                "The value of the :path must either be in asterisk or relative form."
            )

        # get the host and port, depending on the mode of operation
        if self.context.mode is ProxyMode.regular:
            # get the default port
            default_port: Optional[int]
            if scheme is None:
                # can only happen in ordinary CONNECT
                default_port = None
            elif scheme.lower() == b"http":
                default_port = 80
            elif scheme.lower() == b"https":
                default_port = 443
            else:
                raise FlowError(
                    501,
                    f"Regular proxy only supports 'http' and 'https' :scheme, got '{bytes_to_escaped_str(scheme)}'.",
                )
            # check if a target was given and parse it
            if host_header is None:
                raise FlowError(
                    400, "Request to regular proxy requires :authority or host header.",
                )
            host, port = self._get_regular_proxy_host_and_port(host_header)
            if port is None:
                if default_port is None:
                    raise ProtocolError(
                        f"CONNECT method requires port in :authority or host header, got '{bytes_to_escaped_str(host_header)}'."
                    )
                port = default_port
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
            first_line_format=first_line_format,
            method=method,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            http_version=b"HTTP/0.9"
            if isinstance(self.client._http, H0Connection)
            else b"HTTP/3",
            headers=headers,
            content=None,
            timestamp_start=time.time(),
            timestamp_end=None,
        )

    def _build_flow_response(self, headers: Headers) -> http.HTTPResponse:
        pseudo_headers, headers = self._check_and_split_pseudo_headers(
            headers, ResponsePseudoHeaders
        )
        status_code = pseudo_headers.get(ResponsePseudoHeaders.status)
        if status_code is None:
            raise ProtocolError(f"Pseudo header :status is missing.")
        status_code = int(status_code.decode("ascii"))
        return http.HTTPResponse(
            http_version=self._flow.request.http_version,
            status_code=status_code,
            reason=RESPONSES.get(status_code, "Unknown"),
            headers=headers,
            content=None,
            timestamp_start=time.time(),
            timestamp_end=None,
        )

    def _check_and_split_pseudo_headers(
        self, headers: Headers, pseudo_header_type: Type
    ) -> Tuple[Dict[PseudoHeaders, bytes], List[Tuple[bytes, bytes]]]:
        known_pseudo_headers: Dict[bytes, PseudoHeaders] = {
            b":" + x.name.encode("ascii"): x for x in pseudo_header_type
        }
        pseudo_headers: Dict[PseudoHeaders, bytes] = {}
        other_headers: List[Tuple[bytes, bytes]] = []

        # filter out known headers (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.3)
        for header, value in headers:
            if header is None:
                raise ProtocolError("Empty header name is not allowed.")
            if header != header.lower():
                raise ProtocolError(
                    f"Uppercase header name '{bytes_to_escaped_str(header)}' is not allowed."
                )
            if header.startswith(b":"):
                pseudo_header = known_pseudo_headers.get(header)
                if pseudo_header is None:
                    raise ProtocolError(
                        f"Pseudo header '{bytes_to_escaped_str(header)}' is unknown."
                    )
                if pseudo_header in pseudo_headers:
                    raise ProtocolError(
                        f"Pseudo header :{pseudo_header.name} must occur only once."
                    )
                pseudo_headers[pseudo_header] = value
            else:
                other_headers.append((header, value))
        return (pseudo_headers, other_headers)

    async def _get_headers_from_server(self) -> Headers:
        # wait till the headers arrive
        queue = self._data_frames[ProxySide.server]
        while True:
            if queue:
                is_header, headers = queue.popleft()
                if not is_header:
                    raise FlowError(
                        502, "Received data before any headers from server."
                    )
                return headers
            if not self.can_receive[ProxySide.server]:
                raise FlowError(502, "Server connection closed before any headers.")
            await self.wait()

    def _get_regular_proxy_host_and_port(self, host_header: bytes) -> Tuple[str, int]:
        # check for userinfo
        # https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1
        parts = host_header.split(b"@")
        if len(parts) > 1:
            raise ProtocolError(
                "The :authority or host header contains userinfo."
            )  # don't log
        m = PARSE_HOST_HEADER.match(parts[-1].decode("idna"))
        if not m:
            raise ProtocolError(
                f"The :authority or host header '{bytes_to_escaped_str(host_header)}' is malformed."
            )
        host = m.group("host").strip("[]")
        if not m.group("port"):
            return (host, None)
        try:
            port = int(m.group("port"))
            if port < 0 or port > 65535:
                raise ValueError
            return (host, port)
        except ValueError:
            raise ProtocolError(
                f"The port in the :authority or host header '{bytes_to_escaped_str(host_header)}' is invalid."
            )

    def _handle_flow_error(self, exc: FlowError) -> None:
        # log the error
        self.log(
            LogLevel.warn, exc.message, {"stacktrace": "\n" + traceback.format_exc()},
        )

        # try to send the status
        if self.can_send[ProxySide.client]:
            try:
                self.send(
                    to_side=ProxySide.client,
                    headers=[
                        (b":status", str(exc.status).encode("ascii")),
                        (b"server", SERVER_NAME.encode("ascii")),
                        (b"date", formatdate(time.time(), usegmt=True).encode("ascii")),
                    ],
                    end_stream=True,
                )
            except FrameUnexpected:
                pass
            else:
                self.client.transmit()

    def _handle_protocol_error(self, exc: ProtocolError) -> None:
        # log the error
        self.log(
            LogLevel.warn,
            exc.reason_phrase,
            {"stacktrace": "\n" + traceback.format_exc()},
        )

        # close the connection
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
            to_side=from_side.other_side,
            data=self._ws_connections[from_side.other_side.value].send(
                wsproto.events.CloseConnection(code=event.code, reason=event.reason)
            ),
            end_stream=True,
        )
        self.send(
            to_side=from_side,
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

            payload: Union[str, bytes]
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
                            pos_plus_s = pos + s
                            yield (
                                payload[pos:pos_plus_s],
                                True if pos_plus_s == length else False,
                            )
                            pos = pos_plus_s
                    else:
                        # just re-chunk everything into 4kB frames
                        # header len = 4 bytes without masking key and 8 bytes with masking key
                        chunk_size = 4092 if from_side is ProxySide.server else 4088
                        chunks = range(0, len(payload), chunk_size)
                        for i in chunks:
                            i_plus_chunk_size = i + chunk_size
                            yield (
                                payload[i:i_plus_chunk_size],
                                True if i_plus_chunk_size >= len(payload) else False,
                            )

                for chunk, final in get_chunk(websocket_message.content):
                    self.send(
                        to_side=from_side.other_side,
                        data=self._ws_connections[from_side.other_side.value].send(
                            wsproto.events.Message(data=chunk, message_finished=final)
                        ),
                    )

        if self._ws_flow.stream:
            self.send(
                to_side=from_side.other_side,
                data=self._ws_connections[from_side.other_side.value].send(
                    wsproto.events.Message(
                        data=event.data, message_finished=event.message_finished
                    )
                ),
            )

    async def _pump_websocket_data(self) -> bool:
        # pump all messages
        for from_side in ProxySide:
            queue = self._data_frames[from_side]
            while queue:
                is_header, data = queue.popleft()
                if is_header:
                    raise FlowError(
                        502,
                        f"Headers received in websocket flow from {from_side.name}.",
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
                            "Unknown websocket event received.",
                            {
                                "ws_event_type": type(event).__name__,
                                "ws_event_from": from_side.name,
                            },
                        )
        return True

    async def _receive_iterator(
        self, *, from_side: ProxySide, headers_cb: Callable[[Headers], None]
    ) -> AsyncIterable[bytes]:
        # read all data in chunks allowing special handling of headers
        queue = self._data_frames[from_side]
        while True:
            while queue:
                is_header, data = queue.popleft()
                if is_header:
                    headers_cb(data)
                else:
                    yield data
            if not self.can_receive[from_side]:
                break
            await self.wait()

    def build_request_headers(self) -> Headers:
        headers: Headers = []

        # helper function
        def add_header(header: RequestPseudoHeaders, value: Optional[bytes]) -> None:
            if value is not None:
                headers.append((b":" + header.name.encode("ascii"), value))

        # add all translateable pseudo headers
        add_header(RequestPseudoHeaders.method, self._flow.request.data.method)
        add_header(RequestPseudoHeaders.scheme, self._flow.request.data.scheme)
        add_header(RequestPseudoHeaders.path, self._flow.request.data.path)
        if self._flow.metadata.get("websocket", False):
            add_header(RequestPseudoHeaders.protocol, b"websocket")

        # add all but the host header
        for header, value in self._flow.request.headers.fields:
            header = header.lower()
            if header == b"host":
                add_header(RequestPseudoHeaders.authority, value)
            else:
                headers.append((header, value))
        return headers

    def build_response_headers(self) -> Headers:
        # translate the status and append the other headers
        headers: Headers = []
        headers.append(
            (b":status", str(self._flow.response.status_code).encode("ascii"))
        )
        for header, value in self._flow.response.headers.fields:
            headers.append((header.lower(), value))
        return headers

    async def finish_client_request(self) -> bool:
        pass

    def post_data(
        self, from_side: ProxySide, data: bytes, *, is_header: bool = False
    ) -> None:
        self._data_frames[from_side].append((is_header, data))
        self.notify()

    async def prepare_server_response(self, is_websocket: bool) -> None:
        pass

    def provide_host_header(self) -> Optional[bytes]:
        return None

    async def receive_data_and_trailers(
        self,
        *,
        from_side: ProxySide,
        to_object: Union[http.HTTPRequest, http.HTTPResponse],
    ) -> None:
        # store all data and trailers in the object
        to_object.data.content = b""
        async for data in self._receive_iterator(
            from_side=from_side,
            headers_cb=lambda headers: to_object.headers.update(headers),
        ):
            to_object.data.content += data

    async def run(self) -> None:
        try:
            # parse the headers, allow patching
            self._flow.request = self._build_flow_request()
            await self.context.ask("requestheaders", self._flow)

            # complete and log the request
            is_websocket = await self.finish_client_request()
            self._flow.request.timestamp_end = time.time()
            self.log(LogLevel.debug, repr(self._flow.request))

            # allow pre-recorded responses
            await self.context.ask("request", self._flow)
            if is_websocket:
                await self.context.ask("websocket_handshake", self._flow)
            if not self._flow.response:
                # prepare the server side and get the response
                await self.prepare_server_response(is_websocket)
                self._flow.response = self._build_flow_response(
                    await self._get_headers_from_server()
                )
                await self.context.ask("responseheaders", self._flow)
                if is_websocket or self._flow.response.stream:
                    self._flow.response.data.content = None
                else:
                    await self.receive_data_and_trailers(
                        from_side=ProxySide.server, to_object=self._flow.response
                    )
            else:
                # still ask for headers to comply with the protocol
                await self.context.ask("responseheaders", self._flow)

            # allow changing the body
            self.log(LogLevel.debug, repr(self._flow.response))
            await self.context.ask("response", self._flow)

            # always send the headers and handle the rest differently
            self.send(to_side=ProxySide.client, headers=self.build_response_headers())
            if is_websocket:
                await self.run_websocket()

            else:
                # ensure proper response configuration
                if (not self._flow.response.stream) ^ (
                    self._flow.response.data.content is not None
                ):
                    raise FlowError(500, "Streaming and content data set.")

                # stream or send the data
                if self._flow.response.stream:
                    await self.stream_data_and_forward_trailers(
                        from_side=ProxySide.server,
                        to_side=ProxySide.client,
                        cb=self._flow.response.stream,
                    )
                else:
                    self.send(
                        to_side=ProxySide.client,
                        data=self._flow.response.data.content,
                        end_stream=True,
                    )

            # end the response
            self._flow.response.timestamp_end = time.time()
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
            self._ws_buffers = ([], [])
            while await self._pump_websocket_data() and any(self.can_receive):
                await self.wait()
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
        *,
        to_side: ProxySide,
        headers: Optional[Headers] = None,
        data: Optional[bytes] = None,
        end_stream: bool = False,
    ) -> None:
        def internal_send(proto: ConnectionProtocol, stream_id: int) -> None:
            if headers is not None:
                proto._http.send_headers(stream_id, headers, end_stream=False)
            if data is not None:
                proto._http.send_data(stream_id, data, end_stream=False)

        super().send(to_side=to_side, cb=internal_send, end_stream=end_stream)

    async def stream_data_and_forward_trailers(
        self,
        *,
        from_side: ProxySide,
        to_side: ProxySide,
        cb: Optional[Callable[[AsyncIterable[bytes]], AsyncIterable[bytes]]],
    ) -> None:
        # pump data through the callable, sending it and trailers to the other side
        iterator = self._receive_iterator(
            from_side=from_side,
            headers_cb=lambda headers: self.send(to_side=to_side, headers=headers),
        )
        if callable(cb):
            iterator = cb(iterator)
        async for data in iterator:
            self.send(to_side=to_side, data=data)


class PushBridge(HttpBridge):
    def __init__(
        self,
        *,
        client: IncomingProtocol,
        server: OutgoingProtocol,
        headers: Headers,
        push_id: int,
        push_promise_to: HttpBridge,
    ) -> None:
        assert (
            server is not None and push_id is not None and push_promise_to is not None
        )
        super().__init__(
            client=client, server=server, stream_ids=(None, None), headers=headers,
        )
        self._flow.metadata["h2-pushed-stream"] = True
        self._push_id: int = push_id
        self._push_promise_to: HttpBridge = push_promise_to

    async def finish_client_request(self) -> bool:
        # send the push via the bridge that actually triggered it
        push_stream_id = Bridge.send(
            self._push_promise_to,
            to_side=ProxySide.client,
            cb=lambda proto, stream_id: proto._http.send_push_promise(
                stream_id=stream_id, headers=self.build_request_headers(),
            ),
        )

        # store the push stream as unidirectional client stream
        self.set_stream_id(ProxySide.client, push_stream_id)
        self.end_stream_cb(ProxySide.client, push_stream_id)

        # end the request and indicate no websocket
        self._flow.request.content = None if self._flow.request.stream else b""
        return False

    async def prepare_server_response(self, is_websocket: bool) -> None:
        # wait for the server socket
        while not self.has_stream_id(ProxySide.server):
            if not self.server.connected():
                raise FlowError(502, "Server connection closed.")
            await self.wait()

    def provide_host_header(self) -> Optional[bytes]:
        return self._push_promise_to.request.host_header


class RequestBridge(HttpBridge):
    def __init__(
        self,
        *,
        client: IncomingProtocol,
        server: Optional[OutgoingProtocol],
        stream_id: int,
        headers: Headers,
    ) -> None:
        assert stream_id is not None
        super().__init__(
            client=client, server=server, stream_ids=(stream_id, None), headers=headers,
        )

    async def finish_client_request(self) -> bool:
        # CONNECT is only allowed for websockets
        is_websocket: bool = self._flow.metadata.get("websocket", False)
        if self._flow.request.method == "CONNECT" and not is_websocket:
            raise FlowError(501, "CONNECT for QUIC not implemented.")

        # update host header in reverse proxy mode
        if (
            self.context.mode is ProxyMode.reverse
            and not self.context.options.keep_host_header
        ):
            self._flow.request.host_header = (
                self.context.upstream_or_reverse_address[0]
                + ":"
                + str(self.context.upstream_or_reverse_address[1])
            ).encode("idna")

        # handle different content scenarios
        if is_websocket or self._flow.request.stream:
            self._flow.request.data.content = None
        else:
            await self.receive_data_and_trailers(
                from_side=ProxySide.client, to_object=self._flow.request
            )

        # return the websocket status
        return is_websocket

    async def prepare_server_response(self, is_websocket: bool) -> None:
        # connect to the server and open a stream
        if self.context.mode is ProxyMode.regular:
            sni: Optional[str] = None
            for name, value in self._flow.request.headers.fields:
                if name is not None and name.lower() == b"host":
                    sni, _ = self._get_regular_proxy_host_and_port(value)
                    break
            self.server = await self.client.create_outgoing_protocol(
                remote_addr=(self._flow.request.host, self._flow.request.port),
                sni=sni,
                alpn_protocols=H3_ALPN + H0_ALPN,
            )
        self.server.create_stream_id(self)

        # forward the request to the server
        self.send(to_side=ProxySide.server, headers=self.build_request_headers())
        if is_websocket:
            pass
        elif self._flow.request.stream:
            await self.stream_data_and_forward_trailers(
                from_side=ProxySide.client,
                to_side=ProxySide.server,
                cb=self._flow.request.stream,
            )
        else:
            self.send(
                to_side=ProxySide.server,
                data=self._flow.request.data.content,
                end_stream=True,
            )


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


async def quicServer(config: proxy.ProxyConfig, channel: controller.Channel) -> None:
    # prepare all necessary fields for the configuration
    ticket_store = SessionTicketStore()
    context = ProxyContext(config, channel)
    hostname = socket.gethostname().encode("idna")
    certificate, certificate_chain, private_key = context.generate_certificate(
        hostname, {b"localhost", hostname}, b"mitmproxy/quic"
    )

    # start serving
    serve_method = transparent_serve if context.mode is ProxyMode.transparent else serve
    await serve_method(
        context.options.listen_host or "::",
        context.options.listen_port,
        configuration=QuicConfiguration(
            alpn_protocols=H3_ALPN + H0_ALPN
            if context.mode is ProxyMode.regular
            else None,
            is_client=False,
            secrets_log_file=log_master_secret,
            certificate=certificate,
            certificate_chain=certificate_chain,
            private_key=private_key,
        ),
        create_protocol=functools.partial(IncomingProtocol, context),
        session_ticket_fetcher=ticket_store.pop,
        session_ticket_handler=ticket_store.add,
    )
