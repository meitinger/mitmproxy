import asyncio
import collections
import ipaddress
import socket
import struct
from typing import cast, Any, Callable, Dict, Optional, Tuple, Union

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import SessionTicketFetcher, SessionTicketHandler

IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IP_RECVORIGDSTADDR = getattr(socket, "IP_RECVORIGDSTADDR", 20)
sockaddr = tuple


def _native_sockaddr_to_python(sockaddr_in: bytes) -> sockaddr:
    # see makesockaddr in socketmodule.c
    if len(sockaddr_in) < 2:
        raise ValueError("sockaddr_in too short")
    (family,) = struct.unpack("h", sockaddr_in[:2])
    if family == socket.AF_INET:
        if len(sockaddr_in) < 16:
            raise ValueError("sockaddr_in too short for IPv4")
        port, in_addr, _ = struct.unpack("!H4s8s", sockaddr_in[2:16])
        addr = (ipaddress.IPv4Address(in_addr).__str__(), port)
    elif family == socket.AF_INET6:
        if len(sockaddr_in) < 28:
            raise ValueError("sockaddr_in too short for IPv6")
        port, flowinfo, in6_addr, scope_id = struct.unpack("!H16sL", sockaddr_in[2:28])
        addr = (
            ipaddress.IPv6Address(in6_addr).__str__(),
            port,
            flowinfo,
            scope_id,
        )
    else:
        raise NotImplementedError
    return addr


def _calculate_udp_checksum(data: bytes) -> int:
    size = len(data)

    # sum up all full words
    checksum = 0
    for i in range(0, size - (size % 2), 2):
        checksum += (data[i] << 8) | data[i + 1]

    # pad to multiple of words
    if size % 2 != 0:
        checksum += data[size - 1] << 8

    # add the word carryover
    while (checksum & ~0xFFFF) != 0:
        checksum = (checksum >> 16) + (checksum & 0xFFFF)

    # invert the sum and ensure zero is not returned
    checksum = ~checksum & 0xFFFF
    return checksum if checksum != 0 else 0xFFFF


def _build_ipv4_udp_payload_and_pktinfo(
    src: sockaddr, dst: sockaddr, data: bytes
) -> bytes:
    src_ip = socket.inet_pton(socket.AF_INET, src[0])
    dst_ip = socket.inet_pton(socket.AF_INET, dst[0])
    proto = 17  # UDP
    udp_length = 8 + len(data)
    checksum = _calculate_udp_checksum(
        struct.pack(
            "!4s4s2B5H",
            src_ip,
            dst_ip,
            0,
            proto,
            udp_length,
            src[1],
            dst[1],
            udp_length,
            0,
        )
        + data
    )
    udp_header = struct.pack("!4H", src[1], dst[1], udp_length, checksum)
    return udp_header + data, struct.pack("!I4s4s", 0, src_ip, dst_ip)


def _build_ipv6_udp_payload_and_pktinfo(src: sockaddr, dst: sockaddr, data: bytes):
    src_ip = socket.inet_pton(socket.AF_INET6, src[0])
    dst_ip = socket.inet_pton(socket.AF_INET6, dst[0])
    payload_length = 8 + len(data)  # also upd_length
    next_header = 17  # UDP
    checksum = _calculate_udp_checksum(
        struct.pack(
            "!16s16sIH2B4H",
            src_ip,
            dst_ip,
            payload_length,
            0,
            0,
            next_header,
            src[1],
            dst[1],
            payload_length,
            0,
        )
        + data
    )
    udp_header = struct.pack("!4H", src[1], dst[1], payload_length, checksum)
    return udp_header + data, struct.pack("!16sI", src_ip, 0)


def _create_raw_socket(family: int, level: int) -> socket.socket:
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setblocking(False)
        sock.setsockopt(level, socket.IP_TRANSPARENT, 1)
        return sock
    except:
        if sock is not None:
            sock.close()
        raise


class TProxyProtocol(asyncio.BaseProtocol):
    def received_from(self, data: bytes, src: sockaddr, dst: sockaddr,) -> None:
        pass

    def error_received(self, exc: OSError) -> None:
        pass


class TProxyTransport(asyncio.BaseTransport):
    def send_to(self, data: bytes, src: sockaddr, dst: sockaddr,) -> None:
        raise NotImplementedError

    def abort(self) -> None:
        raise NotImplementedError


async def create_tproxy_endpoint(
    loop: asyncio.SelectorEventLoop,
    protocol_factory: Callable[[], TProxyProtocol],
    local_addr: Tuple[str, int],
) -> Tuple[TProxyTransport, TProxyProtocol]:
    host, port = local_addr
    infos = await loop.getaddrinfo(host, port)
    if not infos:
        raise OSError("getaddrinfo() returned empty list")
    sock_family, _, _, _, sock_addr = infos[0]
    sock = None
    try:
        # Create a non-blocking, transparent (any IP) socket, that returns the original destination.
        sock = socket.socket(sock_family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        sock.bind(sock_addr)
    except:
        if sock is not None:
            sock.close()
        raise
    protocol = protocol_factory()
    waiter = loop.create_future()
    transport = _TProxyTransport(loop, sock, sock_addr, protocol, waiter)
    try:
        await waiter
    except:
        transport.close()
        raise
    return transport, protocol


class _TProxyTransport(asyncio.selector_events._SelectorTransport, TProxyTransport):

    _buffer_factory = collections.deque

    def __init__(
        self,
        loop: asyncio.SelectorEventLoop,
        sock: socket.socket,
        sock_addr: sockaddr,
        protocol: TProxyProtocol,
        waiter: asyncio.Future,
    ) -> None:
        super().__init__(loop, sock, protocol)
        self._sock_addr: sockaddr = sock_addr
        self._ip_version: int
        self._send_sock: socket.socket
        if sock.family == socket.AF_INET:
            self._ip_version = 4
            self._send_sock = _create_raw_socket(socket.AF_INET, socket.IPPROTO_IP)
        elif sock.family == socket.AF_INET6:
            self._ip_version = 6
            self._send_sock = _create_raw_socket(socket.AF_INET6, socket.IPPROTO_IPV6)
        else:
            raise NotImplementedError(f"Address family {sock.family} not supported")
        # notify the protocol, start reading and signal complete
        self._loop.call_soon(self._protocol.connection_made, self)
        self._loop.call_soon(self._add_reader, self._sock_fd, self._read_ready)
        self._loop.call_soon(asyncio.futures._set_result_unless_cancelled, waiter, None)

    # override
    def _call_connection_lost(self, exc):
        try:
            super()._call_connection_lost(exc)
        finally:
            self._send_sock.close()
            self._send_sock = None

    def _internal_send(self, data: bytes, src: sockaddr, dst: sockaddr) -> None:
        # Since dst should be an IP optained by self._sock, it has to match its IP version.
        dst_ip = ipaddress.ip_address(dst[0])
        if dst_ip.version != self._ip_version:
            raise ValueError(
                f"The destination {dst} is IPv{dst_ip.version}, expected IPv{self._ip_version}"
            )

        # On local connections, it can happen that src is 0.0.0.0 or ::, change it to 127.0.0.1 or ::1.
        if src[0] == "::":
            src = ("::1",) + src[1:3]
        elif src[0] == "0.0.0.0":
            src = ("127.0.0.1", src[1])

        # If TPROXY is set to redirect to 0.0.0.0, we can listen on ::1 and still get IPv4 traffic.
        # So the actual source IP determines what IP version we use to send back.
        src_ip = ipaddress.ip_address(src[0])
        version = src_ip.version

        # If src is IPv6, dst should be a mapped IPv4 address.
        if version == 4 and self._ip_version != 4:
            dst_ip = dst_ip.ipv4_mapped
            if dst_ip is None:
                raise ValueError(
                    f"Cannot convert source {src} from IPv{self._ip_version} to IPv4"
                )
            dst = (dst_ip.__str__(), dst[1])

        # generate the UDP payload and ancillary data depending on the proto
        if version == 4:
            payload, in_pktinfo = _build_ipv4_udp_payload_and_pktinfo(src, dst, data)
            ancdata = [(socket.IPPROTO_IP, IP_PKTINFO, in_pktinfo)]
            dst = (dst[0], 0)
        elif version == 6:
            payload, in6_pktinfo = _build_ipv6_udp_payload_and_pktinfo(src, dst, data)
            ancdata = [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, in6_pktinfo)]
            dst = (dst[0], 0, 0, 0)
        else:
            raise NotImplementedError

        # send the message
        self._send_sock.sendmsg([payload], ancdata, 0, dst)

    # callback
    def _read_ready(self):
        if self._conn_lost:
            return
        try:
            # 50 bytes is larger than sockaddr_in or sockaddr_in6
            data, ancdata, _, src = self._sock.recvmsg(
                self.max_size, socket.CMSG_LEN(50)
            )
            dst = self._sock_addr
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                    dst = _native_sockaddr_to_python(cmsg_data)
        except (BlockingIOError, InterruptedError):
            pass
        except OSError as exc:
            self._protocol.error_received(exc)
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, "Fatal read error on datagram transport")
        else:
            self._protocol.received_from(data, src, dst)

    # callback
    def _sendto_ready(self):
        while self._buffer:
            data, src, dst = self._buffer.popleft()
            try:
                self._internal_send(data, src, dst)
            except (BlockingIOError, InterruptedError):
                self._buffer.appendleft((data, src, dst))  # try again later
                break
            except OSError as exc:
                self._protocol.error_received(exc)
                return
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(exc, "Fatal write error on datagram transport")
                return
        self._maybe_resume_protocol()
        if not self._buffer:
            self._loop._remove_writer(self._sock_fd)
            if self._closing:
                self._call_connection_lost(None)

    def send_to(self, data: bytes, src: sockaddr, dst: sockaddr) -> None:
        if not data:
            return
        if not self._buffer:
            try:
                self._internal_send(data, src, dst)
                return
            except (BlockingIOError, InterruptedError):
                self._loop._add_writer(self._sock_fd, self._sendto_ready)
            except OSError as exc:
                self._protocol.error_received(exc)
                return
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(exc, "Fatal write error on datagram transport")
                return
        self._buffer.append((bytes(data), src, dst))  # make a copy of data
        self._maybe_pause_protocol()


class QuicTransparentProxy(TProxyProtocol):
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        create_protocol: Callable = QuicConnectionProtocol,
        session_ticket_fetcher: Optional[SessionTicketFetcher] = None,
        session_ticket_handler: Optional[SessionTicketHandler] = None,
        stateless_retry: bool = False,
        stream_handler: Optional[QuicStreamHandler] = None,
    ) -> None:
        self._configuration = configuration
        self._create_protocol = create_protocol
        self._session_ticket_fetcher = session_ticket_fetcher
        self._session_ticket_handler = session_ticket_handler
        self._stateless_retry = stateless_retry
        self._stream_handler = stream_handler
        self._transport: Optional[TProxyTransport] = None
        self._servers: Dict[tuple, QuicServer] = {}

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(TProxyTransport, transport)

    def received_from(self, data: bytes, src: sockaddr, dst: sockaddr,) -> None:
        server: QuicServer
        if dst not in self._servers:
            server = QuicServer(
                configuration=self._configuration,
                create_protocol=self._create_protocol,
                session_ticket_fetcher=self._session_ticket_fetcher,
                session_ticket_handler=self._session_ticket_handler,
                stateless_retry=self._stateless_retry,
                stream_handler=self._stream_handler,
            )
            self._servers[dst] = server
            server.connection_made(QuicTransport(proxy=self, addr=dst, server=server))
        else:
            server = self._servers[dst]
        server.datagram_received(data, src)


class QuicTransport(asyncio.DatagramTransport):
    def __init__(
        self, *, proxy: QuicTransparentProxy, addr: sockaddr, server: QuicServer
    ) -> None:
        self._proxy = proxy
        self._addr = addr
        self._server = server

    def abort(self) -> None:
        self._transport.abort()
        self._proxy._servers.clear()

    def close(self) -> None:
        if not self.is_closing():
            self._proxy._servers.pop(self._addr)

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return (
            self._addr
            if name == "sockname"
            else self._proxy._transport.get_extra_info(name, default)
        )

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._server

    def is_closing(self) -> bool:
        return self._proxy._servers.get(self._addr) is not self._server

    def sendto(self, data: bytes, addr: sockaddr = None) -> None:
        if not self.is_closing():
            self._proxy._transport.send_to(data, self._addr, addr)


async def transparent_serve(
    host: str,
    port: int,
    *,
    configuration: QuicConfiguration,
    create_protocol: Callable = QuicConnectionProtocol,
    session_ticket_fetcher: Optional[SessionTicketFetcher] = None,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stateless_retry: bool = False,
    stream_handler: QuicStreamHandler = None,
) -> QuicTransparentProxy:
    loop = asyncio.get_event_loop()

    _, protocol = await create_tproxy_endpoint(
        loop=loop,
        protocol_factory=lambda: QuicTransparentProxy(
            configuration=configuration,
            create_protocol=create_protocol,
            session_ticket_fetcher=session_ticket_fetcher,
            session_ticket_handler=session_ticket_handler,
            stateless_retry=stateless_retry,
            stream_handler=stream_handler,
        ),
        local_addr=(host, port),
    )
    return cast(QuicTransparentProxy, protocol)
