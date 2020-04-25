import asyncio
import enum
import time
from dataclasses import dataclass
from email.utils import formatdate
from typing import Dict, Tuple, Optional, Set, Union

import mitmproxy
from mitmproxy import controller
from mitmproxy import connections
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import proxy
from mitmproxy import flow as baseflow
from mitmproxy.net.http import url
from mitmproxy.proxy.protocol.http import HTTPMode

import OpenSSL

from .protocol.tls import log_master_secret
from ..version import VERSION


import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.h3.exceptions import FrameUnexpected
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ProtocolNegotiated,
    SecurityNegotiated,
    QuicEvent,
    Headers,
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
SERVER_NAME = "mitmproxy/" + VERSION


@dataclass
class ProxyContext:
    config: proxy.ProxyConfig
    channel: controller.Channel
    mode: HTTPMode


class FlowException(Exception):
    def __init__(self, flow: http.HTTPFlow, status: int, message: str, **kwargs):
        super().__init__(message, **kwargs)
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
    class State(enum.Enum):
        INITIAL = 0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.state = State.INITIAL


class IncomingProtocol(QuicConnectionProtocol, connections.ClientConnection):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, IncomingHandler] = {}
        self._http: Optional[HttpConnection] = None
        self._quic._certificate_fetcher = self._fetch_certificate
        self._local_addr

    @property
    def proxy(self) -> ProxyContext:
        return self._quic.configuration.proxy

    @property
    def address(self) -> Tuple[str, int]:
        return self._http._quic._network_paths[0].addr[0:2]

    @property
    def server(self) -> Tuple[str, int]:
        orig_dst = self._http._quic._network_paths[0].orig_dst
        if orig_dst is None:
            return self._local_addr
        elif orig_dst[0] == "::":
            return ("::1", orig_dst[1])
        elif orig_dst[0] == "0.0.0.0":
            return ("127.0.0.1", orig_dst[1])
        else:
            return orig_dst[0:2]

    # more or less copied from mitmproxy (except we don't have authority format)
    def flow_validate_request(self, flow: http.HTTPFlow) -> None:
        if flow.request.scheme != "https":
            raise FlowException(flow, 505, "QUIC only supports https.")
        if self.proxy.mode is HTTPMode.transparent:
            if flow.request.first_line_format != "relative":
                raise FlowException(
                    flow,
                    405,
                    "Mitmproxy received an absolute-form QUIC request even though it is not running in regular mode. This usually indicates a misconfiguration, please see the mitmproxy mode documentation for details.",
                )
        else:
            if flow.request.first_line_format != "absolute":
                raise FlowException(
                    flow,
                    400,
                    "Invalid QUIC request form (expected: absolute, got: relative)",
                )

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

    def _fetch_certificate(
        self, hello: ClientHello
    ) -> Optional[CertificateWithPrivateKey]:
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
        if self.proxy.mode is HTTPMode.upstream:
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
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
        )
        return CertificateWithPrivateKey(
            cert=cert, chain=chain, private_key=private_key
        )

    def _parse_headers(
        self, headers: Headers
    ) -> Tuple[Optional[str], http.HTTPRequest]:
        headers = []
        authority = None
        path = b"/"
        first_line_format = "relative"
        method = b"GET"
        scheme = b"https"
        protocol = None
        host = self.server[0]
        port = self.server[1]
        for header, value in headers:
            if header == b":authority":
                authority = value
                if self.proxy.mode is not HTTPMode.transparent:
                    host, _, port = authority.partition(b":")
                headers.append((b"host", value))
            elif header == b":method":
                method = value
            elif header == b":path":
                path = value
                if path != b"*" and not path.startswith(b"/"):
                    first_line_format = "absolute"
                    # no need to test for transparent mode as this is done later anyway
                    scheme, host, port, _ = url.parse(path)
            elif header == b":protocol":
                protocol = value.decode()
            elif header and not header.startswith(b":"):
                headers.append((header, value))
        port = int(port)

        return (
            protocol,
            http.HTTPRequest(
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
            ),
        )

    def _create_handler(self, event: HeadersReceived) -> IncomingHandler:
        # create the flow
        flow = http.HTTPFlow(
            client_conn=self, server_conn=None, live=True, mode=self.proxy.mode.name
        )
        flow.metadata[META_STREAM_ID] = event.stream_id

        # parse and check the request headers
        protocol, request = self._parse_headers(event.headers)
        flow.request = request
        self.flow_validate_request(flow)

        # ask and the check again
        self.proxy.channel.ask("requestheaders", flow)
        self.flow_validate_request(flow)

        # basically copied from mitmproxy
        if request.headers.get("expect", "").lower() == "100-continue":
            self.flow_send(flow, headers=[(b":status", b"100")])
            request.headers.pop("expect")

        # check for connect
        if request.method == "CONNECT":
            raise FlowException(
                flow,
                501,
                "Websockets not yet implemented."
                if protocol == "websocket"
                else "CONNECT for QUIC not implemented.",
            )
        else:
            return IncomingHttpHandler(protocol=self, flow=flow)

    def _handle_exception(self, e: FlowException) -> None:
        # ensure a stream id is set
        flow = e.flow
        stream_id = flow.metadata[META_STREAM_ID]
        space = " " * 7
        self.channel.tell(
            "log",
            log.LogEntry(
                f"[QUIC] {self.address[0]}:{self.address[1]} -> {self.server[0]}:{self.server[1]}: {e.message}\n{space}live: {flow.live}\n{space}stream_id: {stream_id}",
                "warn",
            ),
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
                    self._handle_exception(e)


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def quicServer(config: proxy.ProxyConfig, channel: controller.Channel):

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN + H0_ALPN,
        is_client=False,
        secrets_log_file=log_master_secret,
    )

    # load SSL certificate and key
    configuration.load_cert_chain(args.certificate, args.private_key)

    ticket_store = SessionTicketStore()

    return serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
        session_ticket_fetcher=ticket_store.pop,
        session_ticket_handler=ticket_store.add,
    )
