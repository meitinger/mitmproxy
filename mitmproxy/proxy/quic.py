import asyncio
import enum
import functools
import time
import traceback
import socket
from dataclasses import dataclass
from email.utils import formatdate
from typing import Dict, List, Tuple, Optional, Set, Union

import mitmproxy
from mitmproxy import controller
from mitmproxy import connections
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import log
from mitmproxy import proxy
from mitmproxy import flow as baseflow
from mitmproxy.net.http import url

import OpenSSL

from ..net.tls import log_master_secret
from ..version import VERSION


import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection, ProtocolError, FrameUnexpected
from aioquic.h3.events import DataReceived, H3Event, Headers, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ProtocolNegotiated,
    SecurityNegotiated,
    QuicEvent,
)
from aioquic.tls import (
    CertificateWithPrivateKey,
    ClientHello,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
)


HttpConnection = Union[H0Connection, H3Connection]

META_STREAM_ID = "stream-id"
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


@dataclass
class ProxyContext:
    config: proxy.ProxyConfig
    channel: controller.Channel
    mode: ProxyMode

    def generate_certificate(
        self,
        commonname: Optional[bytes],
        sans: Set[bytes],
        organization: Optional[bytes] = None,
    ) -> CertificateWithPrivateKey:
        cert, private_key, chain_file = self.config.certstore.get_cert(
            commonname, list(sans), organization
        )
        with open(chain_file, "rb") as fp:
            chain = load_pem_x509_certificates(fp.read())
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


class FlowException(Exception):
    def __init__(self, flow: http.HTTPFlow, status: int, message: str):
        super().__init__(message)
        self.flow = flow
        self.status = status
        self.message = message


class IncomingHandler:
    def __init__(
        self, *, protocol: QuicConnectionProtocol, flow: http.HTTPFlow
    ) -> None:
        self.protocol = protocol
        self.flow = flow

    def http_event_received(self, event: H3Event) -> None:
        pass


class IncomingHttpHandler(IncomingHandler):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class OutgoingProtocol:
    pass


class IncomingProtocol(QuicConnectionProtocol, connections.ClientConnection):
    """
    Handler for an incoming client connection.
    Spawns of multiple :class:`mitmproxy.proxy.quic.IncomingHandler` for each stream.
    """

    def __init__(self, proxy: ProxyContext, *args, **kwargs) -> None:
        QuicConnectionProtocol.__init__(self, *args, **kwargs)
        connections.ClientConnection.__init__(self, None, None, None)
        self._handlers: Dict[int, IncomingHandler] = {}
        self._http: Optional[HttpConnection] = None
        self._outgoing_connections: Dict[str, OutgoingProtocol] = {}
        self.proxy = proxy
        self._quic._certificate_fetcher = self._fetch_certificate
   
    @property
    def address(self) -> Tuple[str, int]:
        return self._quic._network_paths[0].addr[0:2]

    @address.setter
    def address(self, address):
        if address is not None:
            raise PermissionError

    @property
    def server(self) -> Tuple[str, int]:
        orig_dst = self._quic._network_paths[0].orig_dst
        if orig_dst is None:
            orig_dst = self._transport.get_extra_info("sockname")[0:2]
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

    def flow_send(
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
        stream_id = flow.metadata.get(META_STREAM_ID)
        if stream_id is None:
            raise FlowException(flow, 500, "Flow doesn't countain a stream id.")
        try:
            if headers is not None:
                self._http.send_headers(stream_id, headers, body is None and end_flow)
            if body is not None or (headers is None and end_flow):
                self._http.send_data(stream_id, b"" if body is None else body, end_flow)
        except FrameUnexpected as e:
            raise FlowException(flow, 500, str(e))
        if end_flow:
            flow.live = False
        self.transmit()
        pass

    def _create_or_get_connection(
        self, authority: Optional[Tuple[str, int]] = None
    ) -> OutgoingProtocol:
        if authority is None:
            if self.proxy.mode is ProxyMode.regular:
                raise ValueError(
                    "Parameter authority must not be None for regular proxies."
                )
            elif (
                self.proxy.mode is ProxyMode.upstream
                or self.proxy.mode is ProxyMode.reverse
            ):
                _, host, port, _ = url.parse(self.proxy.config.upstream_server)
                authority = (host, port)
            elif self.proxy.mode is ProxyMode.transparent:
                authority = self.server
            else:
                raise NotImplementedError

    def _fetch_certificate(
        self, hello: ClientHello
    ) -> Optional[CertificateWithPrivateKey]:
        return None
        host: bytes = None
        sans: Set = set()
        organization: str = None

        # create the outgoing connection
        if (
            self.proxy.config.options.upstream_cert
            or self.proxy.config.options.add_upstream_certs_to_client_chain
        ):
            raise NotImplementedError(
                "Incorporating upstream cert not yet implemented."
            )

        # we add the name of server name of the reverse target or upstream proxy
        if self.proxy.mode is ProxyMode.upstream:
            _, upstream, _, _ = url.parse(self.proxy.config.upstream_server)
            sans.add(upstream)

        # add the wanted server name or the ip
        server_ip_or_sni = (
            self.server[0] if hello.server_name is None else hello.server_name
        ).encode("idna")
        sans.add(server_ip_or_sni)
        if host is None:
            host = server_ip_or_sni

        # build the certificate
        cert, private_key, chain_file = self.proxy.config.certstore.get_cert(
            host, list(sans), organization
        )
        chain = load_pem_x509_certificates(chain_file)

        # add the upstream certs to the chain
        if self.proxy.config.options.add_upstream_certs_to_client_chain:
            raise NotImplementedError

        # convert to our library and return
        cert = load_pem_x509_certificates(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        )[0]
        private_key = load_pem_private_key(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key),
            None,
        )
        return CertificateWithPrivateKey(
            cert=cert, chain=chain, private_key=private_key
        )

    def _create_flow_request(self, stream_id: int, headers: Headers) -> http.HTTPFlow:
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

        # create the flow
        flow = http.HTTPFlow(
            client_conn=self, server_conn=None, live=True, mode=self.proxy.mode.name
        )
        flow.metadata[META_STREAM_ID] = stream_id

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
        if self.proxy.mode is ProxyMode.regular:
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
            self.proxy.mode is ProxyMode.upstream
            or self.proxy.mode is ProxyMode.reverse
        ):
            try:
                _, host, port, _ = url.parse(self.proxy.config.upstream_server)
            except ValueError as e:
                raise FlowException(
                    flow, 500, f"Cannot get the upstream config: {repr(e)}"
                )
        elif self.proxy.mode is ProxyMode.transparent:
            host, port = self.server
        else:
            raise NotImplementedError

        # create the request object and return the flow
        flow.request = http.HTTPRequest(
            first_line_format,
            method,
            scheme,
            host,
            port,
            path,
            b"HTTP/0.9" if isinstance(self._http, H0Connection) else b"HTTP/3",
            headers,
            None,
            timestamp_start=time.time(),
            timestamp_end=None,
        )
        return flow

    def _create_handler(self, event: HeadersReceived) -> IncomingHandler:
        # parse the headers and let mitmproxy change them
        flow = self._create_flow_request(event.stream_id, event.headers)
        self.proxy.channel.ask("requestheaders", flow)

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

    def log(
        self, level: LogLevel, msg: str, additional: Optional[Dict[str, str]] = None
    ) -> None:
        if additional is not None:
            msg = ("\n" + " " * 7).join(
                [msg] + [f"{name}: {value}" for (name, value) in additional.items()]
            )
        self.proxy.channel.tell(
            "log",
            log.LogEntry(
                f"[QUIC] {self.address[0]}:{self.address[1]} -> {self.server[0]}:{self.server[1]}: {msg}",
                level.name,
            ),
        )

    def _handle_flow_exception(self, e: FlowException) -> None:
        # ensure a stream id is set
        flow = e.flow
        stream_id = flow.metadata[META_STREAM_ID]
        self.log(
            LogLevel.error if e.status == 500 else LogLevel.warn,
            e.message,
            {"live": flow.live, "stream_id": stream_id},
        )
        assert stream_id is not None

        # close the flow if it is still live
        if flow.live:
            flow.live = False
            flow.error = baseflow.Error(str(e))
            self.proxy.channel.ask("error", flow)
            if self._http is not None:
                try:
                    self._http.send_headers(
                        stream_id,
                        [
                            (b":status", e.status),
                            (b"server", SERVER_NAME.encode()),
                            (b"date", formatdate(time.time(), usegmt=True).encode()),
                        ],
                    )
                    self._http.send_data(stream_id, e.message.encode(), True)
                except FrameUnexpected:
                    # nothing really we can do
                    pass
                self.transmit()

    def _handle_protocol_error(self, e: ProtocolError) -> None:
        # log the error and close the connection
        self.log(
            LogLevel.warn,
            "Protocol error.",
            {"error_code": e.error_code, "reason_phrase": e.reason_phrase},
        )
        self._quic.close(error_code=e.error_code, reason_phrase=e.reason_phrase)
        self.transmit()

    def _handle_event(self, event: H3Event) -> None:
        # create handlers for new streams and forward events
        if isinstance(event, HeadersReceived) and event.stream_id not in self._handlers:
            self._handlers[event.stream_id] = self._create_handler(event)
        elif (
            isinstance(event, (DataReceived, HeadersReceived))
            and event.stream_id in self._handlers
        ):
            self._handlers[event.stream_id].http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        # set the proper http connection
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol.startswith("h3-"):
                self._http = H3Connection(self._quic)
            elif event.alpn_protocol.startswith("hq-"):
                self._http = H0Connection(self._quic)
            self.alpn_proto_negotiated = event.alpn_protocol

        # store the security details
        elif isinstance(event, SecurityNegotiated):
            self.cipher_name = event.cipher_name
            self.tls_version = event.tls_version
            self.tls_established = True
            self.timestamp_tls_setup = time.time()

        # forward to http connection if established
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                try:
                    self._handle_event(http_event)
                except FlowException as e:
                    self._handle_flow_exception(e)
                except ProtocolError as e:
                    self._handle_protocol_error(e)
                except:
                    traceback.print_exc()
                    raise


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def quicServer(config: proxy.ProxyConfig, channel: controller.Channel):
    # parse the proxy mode
    mode_str = config.options.mode.split(":", 1)[0]
    try:
        mode = ProxyMode[mode_str]
    except KeyError:
        raise exceptions.OptionsError(f"Unsupported proxy mode: {mode_str}")

    # prepare all necessary fields for the configuration
    ticket_store = SessionTicketStore()
    context = ProxyContext(config=config, channel=channel, mode=mode)
    hostname = socket.gethostname().encode()
    certificate = context.generate_certificate(
        hostname, {b"localhost", b"::1", b"127.0.0.1", hostname}, b"mitmproxy/quic"
    )

    # start serving
    return serve(
        config.options.listen_host or "::",
        config.options.listen_port,
        configuration=QuicConfiguration(
            alpn_protocols=H3_ALPN + H0_ALPN,
            is_client=False,
            is_transparent=mode == ProxyMode.transparent,
            secrets_log_file=log_master_secret,
            certificate=certificate.cert,
            certificate_chain=certificate.chain,
            private_key=certificate.private_key,
        ),
        create_protocol=functools.partial(IncomingProtocol, context),
        session_ticket_fetcher=ticket_store.pop,
        session_ticket_handler=ticket_store.add,
    )
