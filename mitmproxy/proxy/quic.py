import asyncio
import enum
import functools
import socket
import sys
import time
import traceback
from email.utils import formatdate
from typing import cast, Dict, List, Tuple, Optional, Set, Type, Union

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
from mitmproxy.net.http import url

import OpenSSL

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
from aioquic.quic.connection import QuicConnection
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

META_WEBSOCKET = "websocket"
META_CLIENT_STREAM = "in-stream-id"
META_SERVER_STREAM = "out-stream-id"
SERVER_NAME = "mitmproxy/" + VERSION


class ProxyMode(enum.Enum):
    regular = 1
    upstream = 2
    reverse = 3
    transparent = 4


class LogLevel(enum.Enum):
    debug = 1
    info = 2
    alert = 3
    warn = 4
    error = 5


class KnownPseudoHeaders(enum.Enum):
    method = 1
    scheme = 2
    authority = 3
    path = 4
    protocol = 5


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

    def convert_certificate(self, cert: x509.Certificate) -> certs.Cert:
        return cert.Cert.from_pem(cert.public_bytes(Encoding.PEM))

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

    async def ask(self, mtype, m):
        if not self._channel.should_exit.is_set():
            m.reply = controller.Reply(m)
            await asyncio.run_coroutine_threadsafe(
                self._channel.master.addons.handle_lifecycle(mtype, m),
                self._channel.loop,
            )
            g = m.reply.q.get(block=False)
            if g == exceptions.Kill:
                raise exceptions.Kill()
            return g

    def tell(self, mtype, m):
        if not self._channel.should_exit.is_set():
            m.reply = controller.DummyReply()
            asyncio.run_coroutine_threadsafe(
                self._channel.master.addons.handle_lifecycle(mtype, m),
                self._channel.loop,
            )


class FlowError(Exception):
    def __init__(self, flow: http.HTTPFlow, status: int, message: str):
        super().__init__(message)
        self.flow = flow
        self.status = status
        self.message = message


class ConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, proxy: ProxyContext, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._flows: Dict[int, Tuple[baseflow.Flow, bool]] = {}
        self._http: Optional[HttpConnection] = None
        self._events: asyncio.Queue[QuicEvent] = asyncio.Queue()
        self._local_close: bool = False
        self._is_closed: bool = False
        self.context: ProxyContext = proxy
        self.proto_out: OutgoingProtocol = None
        self.proto_in: IncomingProtocol = None

        # schedule message pump
        asyncio.ensure_future(self._dispatcher(), loop=self._loop)

    @property
    def address(self) -> Tuple[str, int]:
        return self._quic._network_paths[0].addr[0:2]

    @address.setter
    def address(self, address):
        if address is not None:
            raise PermissionError

    @property
    def is_client(self) -> bool:
        return self is self.proto_in

    @property
    def proto_peer(self) -> ConnectionProtocol:
        return self.proto_out if self.is_client else self.proto_in

    def _assign_flow_to_stream_id(
        self, flow: baseflow.Flow, stream_id: Optional[int], end_stream: bool
    ) -> None:
        self._ensure_connected(flow)

        # ensure the flow is assignable
        if (
            META_CLIENT_STREAM if self.is_client else META_SERVER_STREAM
        ) in flow.metadata:
            raise FlowError(
                flow,
                500,
                f"Flow is already assigned to a {'client' if self.is_client else 'server'} stream.",
            )
        existing_conn = flow.client_conn if self.is_client else flow.server_conn
        if existing_conn is not None and existing_conn is not self:
            raise FlowError(
                flow,
                500,
                f"Flow is already assigned to a different {'client' if self.is_client else 'server'} connection.",
            )
        if stream_id is None:
            stream_id = self._quic.get_next_available_stream_id()
        if stream_id in self._flows:
            raise FlowError(
                flow, 500, f"Stream #{stream_id} already has a flow associated.",
            )

        # set the attributes
        if self.is_client:
            flow.client_conn = self
            flow.metadata[META_CLIENT_STREAM] = stream_id
        else:
            flow.server_conn = self
            flow.metadata[META_SERVER_STREAM] = stream_id
        self._flows[stream_id] = (flow, end_stream)

    async def _dispatcher(self) -> None:
        event: QuicEvent = None
        while not isinstance(event, ConnectionTerminated):
            event = await self._events.get()
            try:
                try:
                    # handle known events
                    if isinstance(event, HandshakeCompleted):
                        await self.on_handshake_completed(event)
                    elif isinstance(event, ConnectionTerminated):
                        await self._handle_connection_terminated(event)
                    elif isinstance(event, StreamReset):
                        if self._http is None:
                            await self._handle_raw_data(event.stream_id, None, True)
                        else:
                            await self._handle_http_event(
                                event.stream_id,
                                DataReceived(
                                    stream_id=event.stream_id,
                                    data=b"",
                                    stream_ended=True,
                                ),
                                True,
                            )
                    elif isinstance(event, StreamDataReceived):
                        if self._http is None:
                            await self._handle_raw_data(
                                event.stream_id, event.data, event.end_stream
                            )
                        else:
                            for http_event in self._http.handle_event(event):
                                await self._handle_http_event(
                                    event.stream_id, http_event, event.end_stream
                                )
                except FlowError as exc:
                    await self._handle_flow_error(exc)
                except ProtocolError as exc:
                    await self._handle_protocol_error(exc)
                except Exception as exc:
                    self.log(
                        LogLevel.error,
                        "Uncaught exception.",
                        {
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "stacktrace": traceback.format_stack(),
                        },
                    )
            except:
                # when even logging fails
                traceback.print_exc(file=sys.stderr)

    async def _end_flow(self, flow: baseflow.Flow) -> None:
        if flow.live:
            flow.live = False
            if isinstance(flow, tcp.TCPFlow):
                self.context.tell("tcp_end", flow)

    def _ensure_connected(self, flow: baseflow.Flow) -> None:
        if self._is_closed:
            raise FlowError(flow, 503, f"Connection {self} already closed.")

    def _ensure_flow_ready(self, flow: baseflow.Flow) -> None:
        if not flow.live:
            raise FlowError(flow, 500, "Flow is no longer live.")
        if flow.error is not None:
            raise FlowError(flow, 500, "Flow already failed.")

    def _ensure_flow_type(self, flow: baseflow.Flow, classinfo: Type) -> None:
        if not isinstance(flow, classinfo):
            raise FlowError(
                flow,
                500,
                f"{classinfo.__name__} expected, got '{type(flow).__name__}'.",
            )

    def _ensure_stream_not_ended_and_get_flow(
        self, stream_id: int, end_stream: bool, classinfo: Type
    ) -> baseflow.Flow:
        flow, ended = self._flows[stream_id]
        if ended or self._is_closed:
            raise FlowError(
                flow,
                409,
                f"{'Client' if self.is_client else 'Server'} stream already ended.",
            )
        if end_stream:
            self._flows[stream_id] = (flow, True)
        self._ensure_flow_type(flow, classinfo)
        return flow

    def _get_stream_id_from_flow(self, flow: baseflow.Flow) -> int:
        self._ensure_connected(flow)

        # ensure the flow is properly associated and return the stream id
        existing_conn = flow.client_conn if self.is_client else flow.server_conn
        if existing_conn is None:
            raise FlowError(
                flow,
                500,
                f"Flow is not associated to a {'client' if self.is_client else 'server'} connection.",
            )
        if existing_conn is not self:
            raise FlowError(
                flow,
                500,
                f"Flow is assigned to a different {'client' if self.is_client else 'server'} connection.",
            )
        stream_id = flow.metadata.get(
            META_CLIENT_STREAM if self.is_client else META_SERVER_STREAM
        )
        if stream_id is None:
            raise FlowError(
                flow,
                500,
                f"Flow is not associated to a {'client' if self.is_client else 'server'} stream.",
            )
        if stream_id not in self._flows:
            raise FlowError(
                flow,
                500,
                f"No {'client' if self.is_client else 'server'} stream with id '{stream_id}' found.",
            )
        existing_flow, _ = self._flows[stream_id]
        if existing_flow is not flow:
            raise FlowError(
                flow,
                500,
                f"{'Client' if self.is_client else 'Server'} stream #{stream_id} is assigned to a different flow.",
            )
        return stream_id

    async def _handle_connection_terminated(self, event: ConnectionTerminated) -> None:
        self._is_closed = True
        self.timestamp_end = time.time()
        self.log(
            LogLevel.info
            if event.error_code == QuicErrorCode.NO_ERROR
            else LogLevel.warn,
            "Connection closed.",
            {
                "error_code": event.error_code,
                "reason_phrase": event.reason_phrase,
                "by_peer": not self._local_close,
            },
        )
        for flow, ended in self._flows.items():
            if not ended:
                if self._http is None:
                    self._ensure_flow_type(flow, tcp.TCPFlow)
                    await self._handle_raw_stream_end(flow)
                else:
                    self._ensure_flow_type(flow, http.HTTPFlow)
                    await self._handle_http_stream_end(flow)

    async def _handle_flow_error(self, exc: FlowError) -> None:
        # always log the error
        flow = exc.flow
        self.log(
            LogLevel.warn, exc.message, {"flow": repr(flow)},
        )

        # report the error (and prevent re-entry)
        if flow.error is not None:
            return
        flow.error = baseflow.Error(str(exc))
        await self.context.ask("error", flow)

        # close the flow and send an error if it's a http flow
        if not flow.live:
            return
        await self._end_flow(flow)
        if (
            isinstance(flow, http.HTTPFlow)
            and isinstance(flow.client_conn, ConnectionProtocol)
            and not flow.client_conn._is_closed
            and flow.client_conn._http is not None
        ):
            try:
                flow.client_conn._http.send_headers(
                    flow.client_conn._get_stream_id_from_flow(flow),
                    [
                        (b":status", exc.status),
                        (b"server", SERVER_NAME.encode()),
                        (b"date", formatdate(time.time(), usegmt=True).encode()),
                    ],
                    end_stream=True,
                )
            except FrameUnexpected:
                pass
            else:
                flow.client_conn.transmit()

    async def _handle_http_event(
        self, stream_id: int, event: H3Event, end_stream: bool
    ) -> None:
        flow: http.HTTPFlow
        if isinstance(event, HeadersReceived) and stream_id not in self._flows:
            flow = http.HTTPFlow(
                self.proto_in, self.proto_out, True, self.context.mode.name
            )
            self._assign_flow_to_stream_id(flow, stream_id, end_stream)
        else:
            if not isinstance(
                event, (DataReceived, HeadersReceived, PushPromiseReceived)
            ):
                return self.log(
                    LogLevel.debug,
                    "Unknown H3 event received.",
                    {"event": event.__name__},
                )
            if stream_id not in self._flows:
                return self.log(
                    LogLevel.debug,
                    "H3 event received before any headers.",
                    {
                        "event": event.__name__,
                        "stream_id": stream_id,
                        "end_stream": end_stream,
                    },
                )
            flow = self._ensure_stream_not_ended_and_get_flow(
                stream_id, end_stream, http.HTTPFlow
            )

        # handle event and stream end
        if not isinstance(event, DataReceived) or len(event.data) > 0 or not end_stream:
            await self.on_http_event(flow, event)
        if end_stream:
            await self._handle_http_stream_end(flow)

    async def _handle_http_stream_end(self, flow: http.HTTPFlow) -> None:
        # end the flow if either no peer is connected or the peer ended as well
        await self.on_http_completed(flow)
        flow_proto_peer = cast(
            ConnectionProtocol, flow.server_conn if self.is_client else flow.client_conn
        )
        if (
            flow_proto_peer is None
            or flow_proto_peer._is_closed
            or flow_proto_peer._has_stream_ended(
                flow_proto_peer._get_stream_id_from_flow(flow)
            )
        ):
            await self._end_flow(flow)

    async def _handle_protocol_error(self, exc: ProtocolError) -> None:
        # close the connection (will be logged when ConnectionTerminated is handled)
        self._local_close = True
        self._quic.close(error_code=exc.error_code, reason_phrase=exc.reason_phrase)
        self.transmit()

    async def _handle_raw_data(
        self, stream_id: int, data: Optional[bytes], end_stream: bool
    ) -> None:
        # ensure a peer was set
        if self.proto_peer is None:
            self.log(
                LogLevel.info,
                f"Raw data received but no {'server' if self.is_client else 'client'} connection set.",
                {
                    "stream_id": stream_id,
                    "end_stream": end_stream,
                    "data": "" if data is None else data.decode(),
                },
            )
            return

        # create or get the flow
        flow: tcp.TCPFlow
        if stream_id not in self._flows:
            flow = tcp.TCPFlow(self.proto_in, self.proto_out, True)
            self._assign_flow_to_stream_id(flow, stream_id, end_stream)
            self.proto_peer._assign_flow_to_stream_id(flow, None, False)
            await self.context.ask("tcp_start", flow)
        else:
            flow = self._ensure_stream_not_ended_and_get_flow(
                stream_id, end_stream, tcp.TCPFlow
            )

        # relay the message
        stream_id_peer = self.proto_peer._get_stream_id_from_flow(flow)
        if data is not None:
            tcp_message = tcp.TCPMessage(self.is_client, data)
            flow.messages.append(tcp_message)
            await self.context.ask("tcp_message", flow)
        self._ensure_flow_ready(flow)
        self.proto_peer._quic.send_stream_data(
            stream_id_peer, b"" if data is None else tcp_message.content, end_stream
        )

        # handle end of stream
        if end_stream:
            await self._handle_raw_stream_end(flow)

    async def _handle_raw_stream_end(self, flow: tcp.TCPFlow) -> None:
        # end the flow if both streams ended
        if (
            self.proto_peer is None
            or self.proto_peer._is_closed
            or self.proto_peer._has_stream_ended(
                self.proto_peer._get_stream_id_from_flow(flow)
            )
        ):
            await self._end_flow(flow)

    def _has_stream_ended(self, stream_id: int) -> bool:
        return self._flows[stream_id][1]

    def close(self) -> None:
        self._local_close = True
        super().close()

    def connected(self):
        return not self._is_closed

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        if additional is not None:
            msg = ("\n" + " " * 7).join(
                [msg] + [f"{name}: {value}" for (name, value) in additional.items()]
            )
        self.context.tell("log", log.LogEntry(self.log_format(msg), level.name))

    def log_format(self, msg: str) -> str:
        # should be overridden in subclass
        return msg

    async def on_handshake_completed(self, event: HandshakeCompleted) -> None:
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

    async def on_http_completed(self, flow: http.HTTPFlow) -> None:
        pass

    async def on_http_event(self, flow: http.HTTPFlow, event: H3Event) -> None:
        pass

    def quic_event_received(self, event: QuicEvent) -> None:
        self._events.put_nowait(event)

    def send_http(
        self,
        flow: http.HTTPFlow,
        headers: Optional[Headers] = None,
        body: Optional[bytes] = None,
        end_flow: bool = False,
    ) -> None:
        if self._http is None:
            raise FlowError(flow, 503, "No HTTP connection available.")
        self._ensure_flow_ready(flow)
        stream_id = self._get_stream_id_from_flow(flow)
        try:
            if headers is not None:
                self._http.send_headers(stream_id, headers, body is None and end_flow)
            if body is not None or (headers is None and end_flow):
                self._http.send_data(stream_id, b"" if body is None else body, end_flow)
        except FrameUnexpected as e:
            raise FlowError(flow, 500, str(e))
        else:
            self.transmit()


class OutgoingProtocol(ConnectionProtocol, connections.ServerConnection):
    def __init__(self, proto_in: IncomingProtocol, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, proto_in.context, *args, **kwargs)
        connections.ServerConnection.__init__(self, None, None, None)
        self.proto_out = self
        self.proto_in = proto_in

    @property
    def source_address(self) -> Tuple[str, int]:
        return self._transport.get_extra_info("sockname")[0:2]

    @source_address.setter
    def source_address(self, source_address):
        if source_address is not None:
            raise PermissionError

    def log_format(self, msg: str) -> str:
        return f"[QUIC-out] {self.source_address[0]}:{self.source_address[1]} -> {self.address[0]}:{self.address[1]}: {msg}"

    async def on_handshake_completed(self, event: HandshakeCompleted) -> None:
        await super().on_handshake_completed(event)
        self.cert = self.context.convert_certificate(event.certificates[0])
        self.server_certs = [
            self.context.convert_certificate(cert) for cert in event.certificates[1:]
        ]


class IncomingProtocol(ConnectionProtocol, connections.ClientConnection):
    def __init__(self, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, *args, **kwargs)
        connections.ClientConnection.__init__(self, None, None, None)
        self._quic.tls.client_hello_cb = self._handle_client_hello
        self.proto_in = self

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

    def log_format(self, msg: str) -> str:
        return f"[QUIC-in] {self.address[0]}:{self.address[1]} -> {self.server[0]}:{self.server[1]}: {msg}"

    async def _begin_http_request(
        self, flow: http.HTTPFlow, event: HeadersReceived
    ) -> None:
        # parse the headers and allow patching
        flow.request = self._build_http_flow_request(flow, event.headers)
        await self.context.ask("requestheaders", flow)

        # basically copied from mitmproxy
        if flow.request.headers.get("expect", "").lower() == "100-continue":
            self.send_http(flow, headers=[(b":status", b"100")])
            flow.request.headers.pop("expect")

        # check for connect
        if flow.request.method == "CONNECT":
            raise FlowError(
                flow,
                501,
                "Websockets not yet implemented."
                if flow.metadata[META_WEBSOCKET]
                else "CONNECT for QUIC not implemented.",
            )

        # handle different content scenarios
        if flow.request.stream:
            flow.request.data.content = None
            await self._end_http_request(flow)
        else:
            flow.request.data.content = b""

    def _build_http_flow_request(
        self, flow: http.HTTPFlow, headers: Headers
    ) -> http.HTTPRequest:
        known_pseudo_headers: Dict[bytes, KnownPseudoHeaders] = {
            b":" + x.name.encode(): x for x in KnownPseudoHeaders
        }
        pseudo_headers: Dict[KnownPseudoHeaders, bytes] = {}
        ordinary_headers: List[Tuple[bytes, bytes]] = []
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
        for header, value in headers:
            if self._check_header_and_is_pseudo(header):
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
                ordinary_headers.append((header, value))

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
                ordinary_headers.append((b"host", host_header))

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
                scheme = None
                path = None
                first_line_format = "authority"
            else:
                # extended CONNECT (https://tools.ietf.org/html/draft-ietf-httpbis-h2-websockets-07#section-4)
                if protocol.lower() != b"websocket":
                    raise ProtocolError(
                        f"Only 'websocket' is supported for :protocol header, got '{protocol.decode()}'."
                    )
                flow.metadata[META_WEBSOCKET] = True
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
                raise FlowError(
                    flow,
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
                    flow,
                    501,
                    f"Regular proxy only supports 'http' and 'https' :scheme, got '{scheme.decode()}'.",
                )
        elif (
            self.context.mode is ProxyMode.upstream
            or self.context.mode is ProxyMode.reverse
        ):
            host, port = self.context.upstream_or_reverse_address
        elif self.context.mode is ProxyMode.transparent:
            host, port = self.server
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
            b"HTTP/0.9" if isinstance(self._http, H0Connection) else b"HTTP/3",
            ordinary_headers,
            None,
            timestamp_start=time.time(),
            timestamp_end=None,
        )

    def _check_header_and_is_pseudo(self, header: Optional[bytes]) -> bool:
        if header is None:
            raise ProtocolError("Empty header name is not allowed.")
        if header != header.lower():
            raise ProtocolError(
                f"Uppercase header name '{header.decode()}' is not allowed."
            )
        return header.startswith(b":")

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
        await protocol.wait_connect()
        return protocol

    async def _end_http_request(self, flow: http.HTTPFlow) -> None:
        flow.request.timestamp_end = time.time()
        self.log("request", "debug", [repr(flow.request)])

        # update host header in reverse proxy mode
        if (
            self.context.mode is ProxyMode.reverse
            and not self.context.options.keep_host_header
        ):
            flow.request.host_header = self.context.upstream_or_reverse_address

        await self.context.ask("request", flow)

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
            self.proto_out = asyncio.run_coroutine_threadsafe(
                self._create_outgoing_protocol(
                    remote_addr=self.server
                    if self.context.mode is ProxyMode.transparent
                    else self.context.upstream_or_reverse_address,
                    sni=hello.server_name,
                    alpn_protocols=hello.alpn_protocols,
                ),
                self._loop,
            ).result()
            tls.alpn_negotiated = self.proto_out.alpn_proto_negotiated

            # copy over all possible certificate data if requested
            if self.context.options.upstream_cert:
                upstream_cert = self.proto_out.cert
                sans.update(upstream_cert.altnames)
                if upstream_cert.cn:
                    host = upstream_cert.cn.decode("utf8").encode("idna")
                    sans.add(host)
                if upstream_cert.organization:
                    organization = upstream_cert.organization
            if self.context.options.add_upstream_certs_to_client_chain:
                extra_chain = self.proto_out.server_certs

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
        future.result()
        self._process_events()
        self.transmit()

    def _update_http_flow_request_headers(
        self, request: http.HTTPRequest, headers: Headers
    ) -> None:
        # only allow non-pseudo headers (https://tools.ietf.org/html/draft-ietf-quic-http-27#section-4.1.1.1)
        for header, value in headers:
            if self._check_header_and_is_pseudo(header):
                raise ProtocolError(
                    f"Pseudo header '{header.decode()}' not allowed in trailers."
                )
            request.headers.add(header, value)

    def datagram_received(
        self, data: bytes, addr: Tuple, orig_dst: Optional[Tuple] = None
    ) -> None:
        if self.tls_established:
            self._quic.receive_datagram(
                cast(bytes, data), addr, self._loop.time(), orig_dst
            )
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
                orig_dst,
            ).add_done_callback(self._process_events_and_transmit)

    async def on_handshake_completed(self, event: HandshakeCompleted) -> None:
        await super().on_handshake_completed(event)
        self.mitmcert = self.context.convert_certificate(event.certificates[0])

    async def on_http_completed(self, flow: http.HTTPFlow) -> None:
        if not flow.request.stream:
            await self._end_http_request(flow)

    async def on_http_event(self, flow: http.HTTPFlow, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            if flow.request is None:
                await self._begin_http_request(flow, event)
            else:
                if not flow.request.stream:
                    self._update_http_flow_request_headers(flow.request, event.headers)
        elif isinstance(event, DataReceived):
            if not flow.request.stream:
                flow.request.data.content += event.data


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def quicServer(config: proxy.ProxyConfig, channel: controller.Channel):
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
