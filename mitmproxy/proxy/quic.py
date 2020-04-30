import asyncio
import enum
import functools
import queue
import socket
import sys
import time
import threading
import traceback
from dataclasses import dataclass
from email.utils import formatdate
from typing import cast, Dict, List, Tuple, Optional, Set, Union

import mitmproxy
from mitmproxy import certs
from mitmproxy import controller
from mitmproxy import connections
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import log
from mitmproxy import proxy
from mitmproxy import flow as baseflow
from mitmproxy.net.http import url

import OpenSSL

import certifi
from cryptography import x509
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
    ProtocolNegotiated,
    QuicEvent,
    StreamReset,
)
from aioquic.quic.packet import QuicErrorCode
from aioquic.tls import (
    CertificateWithPrivateKey,
    ClientHello,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
)


HttpConnection = Union[H0Connection, H3Connection]

META_WEBSOCKET = "websocket"
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
        super().__init__()
        self.upstream_or_reverse_address: Tuple[bytes, int]
        self.options = config.options
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
    ) -> CertificateWithPrivateKey:
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
        return CertificateWithPrivateKey(
            cert=load_pem_x509_certificates(
                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.x509)
            )[0],
            chain=chain,
            private_key=load_pem_private_key(
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


class FlowException(Exception):
    def __init__(self, flow: http.HTTPFlow, status: int, message: str):
        super().__init__(message)
        self.flow = flow
        self.status = status
        self.message = message


class ConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, conn_name: str, proxy: ProxyContext, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._flows: Dict[int, http.HTTPFlow] = {}
        self._http: Optional[HttpConnection] = None
        self._flow_conn_name: str = conn_name
        self._flow_meta_id: str = conn_name + "_stream_id"
        self._events: asyncio.Queue[QuicEvent] = asyncio.Queue()
        self.context: ProxyContext = proxy
        
        # schedule message pump
        asyncio.ensure_future(self._dispatcher(), self._loop)

    @property
    def address(self) -> Tuple[str, int]:
        return self._quic._network_paths[0].addr[0:2]

    @address.setter
    def address(self, address):
        if address is not None:
            raise PermissionError

    async def _dispatcher(self) -> None:
        event: H3Event = None
        while not isinstance(event, ConnectionTerminated):
            event = await self._events.get()
            try:
                try:
                    if isinstance(event, HandshakeCompleted):
                        await self.on_handshake_completed(event)
                    elif isinstance(event, ConnectionTerminated):
                        await self.on_connection_terminated(
                            event.error_code, event.reason_phrase
                        )
                    elif isinstance(event, StreamReset):
                        await self._handle_stream_reset(event)

                    # forward to http connection if established
                    if self._http is not None:
                        for http_event in self._http.handle_event(event):
                            await self._handle_http_event(http_event)
                except FlowException as exc:
                    await self._handle_flow_exception(exc)
                except ProtocolError as exc:
                    self._quic.close(
                        error_code=exc.error_code, reason_phrase=exc.reason_phrase
                    )
                    self.transmit()
                except Exception as exc:
                    self.log(
                        LogLevel.error,
                        "Uncaught exception.",
                        {"error": repr(exc), "stacktrace": traceback.format_stack()},
                    )
            except:
                traceback.print_exc(file=sys.stderr)

    async def _handle_flow_exception(self, exc: FlowException) -> None:
        # ensure a stream id is set
        flow = exc.flow
        stream_id = flow.metadata[self._flow_meta_id]
        self.log(
            LogLevel.warn, exc.message, {"live": flow.live, "stream_id": stream_id},
        )
        assert stream_id is not None

        # report the error
        if not flow.live:
            return
        flow.error = baseflow.Error(str(exc))
        await self.context.ask("error", flow)
        if not flow.live:
            return

        # send and error and close the flow
        if self._http is not None:
            try:
                self._http.send_headers(
                    stream_id,
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
                self.transmit()
        flow.live = False
        await self.on_flow_ended(flow, exc.status, False)

    async def _handle_http_event(self, event: H3Event) -> None:
        flow: http.HTTPFlow
        if isinstance(event, HeadersReceived) and event.stream_id not in self._flows:
            flow = http.HTTPFlow(None, None, True, self.context.mode.name)
            setattr(flow, self._flow_conn_name, self)
            flow.metadata[self._flow_meta_id] = event.stream_id
            self._flows[event.stream_id] = flow
        else:
            if not isinstance(
                event, (DataReceived, HeadersReceived, PushPromiseReceived)
            ):
                return self.log(
                    LogLevel.debug,
                    "Unknown H3 event received.",
                    {"event": event.__name__},
                )
            if event.stream_id not in self._flows:
                return self.log(
                    LogLevel.debug,
                    "H3 event received for unknown stream.",
                    {"event": event.__name__, "stream_id": event.stream_id},
                )
            flow = self._flows[event.stream_id]
        try:
            await self.on_flow_http_event(flow, event)
        finally:
            if event.stream_ended and flow.live:
                flow.live = False
                await self.on_flow_ended(flow, QuicErrorCode.NO_ERROR, True)

    async def _handle_stream_reset(self, event: StreamReset) -> None:
        if event.stream_id not in self._flows:
            return self.log(
                LogLevel.debug,
                "Stream reset received for unknown stream.",
                {"stream_id": event.stream_id, "error_code": event.error_code},
            )
        flow = self._flows[event.stream_id]
        if flow.live:
            flow.live = False
            await self.on_flow_ended(flow, event.error_code, True)

    async def flow_create_stream(
        self, flow: http.HTTPFlow, is_unidirectional: bool = False
    ) -> int:
        assert getattr(flow, self._flow_conn_name) is None
        setattr(flow, self._flow_conn_name, self)
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional)
        flow.metadata[self._flow_meta_id] = stream_id
        self._flows[stream_id] = flow
        return stream_id

    async def flow_send(
        self,
        flow: http.HTTPFlow,
        headers: Optional[Headers] = None,
        body: Optional[bytes] = None,
        end_flow: bool = False,
    ) -> None:
        if not flow.live:
            raise FlowException(flow, 500, "Flow is not live.")
        if self._http is None:
            raise FlowException(flow, 503, "No HTTP connection available.")
        stream_id = flow.metadata.get(self._flow_meta_id)
        assert stream_id is not None
        try:
            if headers is not None:
                self._http.send_headers(stream_id, headers, body is None and end_flow)
            if body is not None or (headers is None and end_flow):
                self._http.send_data(stream_id, b"" if body is None else body, end_flow)
        except FrameUnexpected as e:
            raise FlowException(flow, 500, str(e))
        else:
            self.transmit()
        if end_flow:
            flow.live = False
            await self.on_flow_ended(flow, QuicErrorCode.NO_ERROR, False)

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

    async def on_connection_terminated(
        self, error_code: int, reason_phrase: str
    ) -> None:
        self.log(
            LogLevel.info if error_code == QuicErrorCode.NO_ERROR else LogLevel.warn,
            "Connection closed.",
            {"error_code": error_code, "reason_phrase": reason_phrase},
        )

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

    async def on_flow_ended(
        self, flow: http.HTTPFlow, error_code: int, by_remote: bool
    ) -> None:
        pass

    async def on_flow_http_event(self, flow: http.HTTPFlow, event: H3Event) -> None:
        pass

    def quic_event_received(self, event: QuicEvent) -> None:
        self._events.put_nowait(event)


class OutgoingProtocol(ConnectionProtocol, connections.ServerConnection):
    def __init__(self, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, "server_conn", *args, **kwargs)
        connections.ServerConnection.__init__(self, None, None, None)

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


class IncomingProtocol(ConnectionProtocol, connections.ClientConnection):
    def __init__(self, *args, **kwargs) -> None:
        ConnectionProtocol.__init__(self, "client_conn", *args, **kwargs)
        connections.ClientConnection.__init__(self, None, None, None)
        self._default_outgoing_protocol: OutgoingProtocol = None
        self._quic._certificate_fetcher = self._fetch_certificate

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

    async def _ensure_default_outgoing_protocol(self) -> None:
        if self._default_outgoing_protocol is None:
            connection = QuicConnection(
                configuration=QuicConfiguration(
                    alpn_protocols=H3_ALPN + H0_ALPN,
                    is_client=True,
                    server_name=None if self.sni is None else self.sni.decode("idna"),
                    secrets_log_file=log_master_secret,
                )
            )
            _, protocol = await loop.create_datagram_endpoint(
                lambda: OutgoingProtocol(connection),
                local_addr=(local_host, local_port),
            )
            protocol = cast(QuicConnectionProtocol, protocol)
            protocol.connect(addr)
            # self._default_outgoing_protocol =
            await self._default_outgoing_protocol.wait_connect()

    def _process_events_and_transmit(self, future: asyncio.Future) -> None:
        future.result()
        self._process_events()
        self.transmit()

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

    def _create_or_get_connection(
        self, authority: Optional[Tuple[str, int]] = None
    ) -> OutgoingProtocol:
        if authority is None:
            if self.context.mode is ProxyMode.regular:
                raise ValueError(
                    "Parameter authority must not be None for regular proxies."
                )
            elif (
                self.context.mode is ProxyMode.upstream
                or self.context.mode is ProxyMode.reverse
            ):
                authority = self.context.upstream_or_reverse_address
            elif self.context.mode is ProxyMode.transparent:
                authority = self.server
            else:
                raise NotImplementedError

    def _fetch_certificate(
        self, hello: ClientHello
    ) -> Optional[CertificateWithPrivateKey]:
        host: bytes = None
        sans: Set = set()
        organization: str = None

        # store the sni
        self.sni = (
            None if hello.server_name is None else hello.server_name.encode("idna")
        )

        # create the outgoing connection if the destination is known and it's necessary
        if self.context.mode is not ProxyMode.regular and (
            self.context.options.upstream_cert
            or self.context.options.add_upstream_certs_to_client_chain
        ):
            asyncio.run_coroutine_threadsafe(
                self._ensure_default_outgoing_protocol(), self._loop
            ).result()

            # copy over all possible values
            upstream_cert = self._default_outgoing_protocol.cert
            sans.update(upstream_cert.altnames)
            if upstream_cert.cn:
                host = upstream_cert.cn.decode("utf8").encode("idna")
                sans.add(host)
            if upstream_cert.organization:
                organization = upstream_cert.organization

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
        return self.context.generate_certificate(
            host,
            list(sans),
            organization,
            extra_chain=self._default_outgoing_protocol.server_certs
            if self.context.options.add_upstream_certs_to_client_chain
            else None,
        )

    def _create_request(
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
            if header is None:
                raise ProtocolError("Empty header name is not allowed.")
            if header != header.lower():
                raise ProtocolError(
                    f"Uppercase header name '{header.decode()}' is not allowed."
                )
            if header.startswith(b":"):
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
                raise FlowException(
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
                raise FlowException(
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

    async def on_flow_http_event(self, flow: http.HTTPFlow, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):



    def _create_handler(self, event: HeadersReceived) -> IncomingHandler:
        # parse the headers and let mitmproxy change them
        flow = self._create_flow_request(event.stream_id, event.headers)
        print("O1")
        self.log(LogLevel.warn, "ok")
        self.context.ask("requestheaders", flow)
        print("O2")

        # basically copied from mitmproxy
        if flow.request.headers.get("expect", "").lower() == "100-continue":
            self.flow_send(flow, headers=[(b":status", b"100")])
            flow.request.headers.pop("expect")

        # check for connect
        if flow.request.method == "CONNECT":
            raise FlowException(
                flow,
                501,
                "Websockets not yet implemented."
                if flow.metadata[META_WEBSOCKET]
                else "CONNECT for QUIC not implemented.",
            )
        else:
            return IncomingHttpHandler(protocol=self, flow=flow)

    async def on_handshake_completed(self, event: HandshakeCompleted) -> None:
        await super().on_handshake_completed(event)
        self.mitmcert = self.context.convert_certificate(event.certificates[0])


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
    certificate = context.generate_certificate(
        hostname, {b"localhost", b"::1", b"127.0.0.1", hostname}, b"mitmproxy/quic"
    )

    # start serving
    return serve(
        context.options.listen_host or "::",
        context.options.listen_port,
        configuration=QuicConfiguration(
            alpn_protocols=H3_ALPN + H0_ALPN,
            is_client=False,
            is_transparent=context.mode is ProxyMode.transparent,
            secrets_log_file=log_master_secret,
            certificate=certificate.cert,
            certificate_chain=certificate.chain,
            private_key=certificate.private_key,
        ),
        create_protocol=functools.partial(IncomingProtocol, context),
        session_ticket_fetcher=ticket_store.pop,
        session_ticket_handler=ticket_store.add,
    )
