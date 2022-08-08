"""
This module defines "server instances", which manage
the TCP/UDP servers spawned my mitmproxy as specified by the proxy mode.

Example:

    mode = ProxyMode.parse("reverse:https://example.com")
    inst = ServerInstance.make(mode, manager_that_handles_callbacks)
    await inst.start()
    # TCP server is running now.
"""
from __future__ import annotations

import asyncio
import enum
import errno
import struct
import sys
import typing
from abc import ABCMeta, abstractmethod
from contextlib import contextmanager
from typing import ClassVar, Generic, TypeVar, cast, get_args

from mitmproxy import ctx, flow, log
from mitmproxy.connection import Address
from mitmproxy.master import Master
from mitmproxy.net import udp
from mitmproxy.proxy import commands, layers, mode_specs, server
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import Layer
from mitmproxy.utils import asyncio_utils, human


class ProxyConnectionHandler(server.LiveConnectionHandler):
    master: Master

    def __init__(self, master, r, w, options, mode):
        self.master = master
        super().__init__(r, w, options, mode)
        self.log_prefix = f"{human.format_address(self.client.peername)}: "

    async def handle_hook(self, hook: commands.StartHook) -> None:
        with self.timeout_watchdog.disarm():
            # We currently only support single-argument hooks.
            (data,) = hook.args()
            await self.master.addons.handle_lifecycle(hook)
            if isinstance(data, flow.Flow):
                await data.wait_for_resume()  # pragma: no cover

    def log(self, message: str, level: str = "info") -> None:
        x = log.LogEntry(self.log_prefix + message, level)
        asyncio_utils.create_task(
            self.master.addons.handle_lifecycle(log.AddLogHook(x)),
            name="ProxyConnectionHandler.log",
        )


M = TypeVar('M', bound=mode_specs.ProxyMode)


class ServerManager(typing.Protocol):
    connections: dict[tuple, ProxyConnectionHandler]

    async def update_instance(self, instance: ServerInstance):
        ...  # pragma: no cover

    @contextmanager
    def register_connection(self, connection_id: tuple, handler: ProxyConnectionHandler):
        ...  # pragma: no cover


class ServerInstanceState(enum.Enum):
    STOPPED = 1
    START_PENDING = 2
    RUNNING = 3
    STOP_PENDING = 4


class ServerInstance(Generic[M], metaclass=ABCMeta):

    __modes: ClassVar[dict[str, type[ServerInstance]]] = {}

    def __init__(self, mode: M, manager: ServerManager):
        self.mode: M = mode
        self.manager: ServerManager = manager
        self._exception: BaseException | None = None
        self._state: ServerInstanceState = ServerInstanceState.STOPPED

    def __init_subclass__(cls, **kwargs):
        """Register all subclasses so that make() finds them."""
        # extract mode from Generic[Mode].
        mode = get_args(cls.__orig_bases__[0])[0]
        if mode != M:
            assert mode.type not in ServerInstance.__modes
            ServerInstance.__modes[mode.type] = cls

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} mode={self.mode.full_spec}, state={self.state}, exception={self.exception}>"

    @staticmethod
    def make(
        mode: mode_specs.ProxyMode | str,
        manager: ServerManager,
    ) -> ServerInstance:
        if isinstance(mode, str):
            mode = mode_specs.ProxyMode.parse(mode)
        return ServerInstance.__modes[mode.type](mode, manager)

    async def report(self, *, state: ServerInstanceState | None = None, exception: BaseException | None = None) -> None:
        if state is not None and self.state is not state:
            self._state = state
        elif self._exception is exception:
            return
        self._exception = exception
        await self.manager.update_instance(self)

    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

    @property
    def state(self) -> ServerInstanceState:
        return self._state

    @property
    def exception(self) -> BaseException | None:
        return self._exception

    @property
    @abstractmethod
    def listen_addrs(self) -> tuple[Address, ...]:
        pass


class AsyncioServerInstance(ServerInstance[M], metaclass=ABCMeta):
    server: asyncio.Server | udp.UdpServer | None = None

    def __init__(self, mode: M, manager: ServerManager):
        super().__init__(mode, manager)
        self._lock: asyncio.Lock = asyncio.Lock()
        self._listen_addr: tuple[Address, ...] = tuple()

    async def start(self):
        host = self.mode.listen_host(ctx.options.listen_host)
        port = self.mode.listen_port(ctx.options.listen_port)
        async with self._lock:
            if self.server is not None:
                return
            await self.report(state=ServerInstanceState.START_PENDING)
            try:
                self.server = await self.listen(host, port)
            except OSError as e:
                await self.report(state=ServerInstanceState.STOPPED, exception=e)
                message = f"{self.log_desc} failed to listen on {host or '*'}:{port} with {e}"
                if e.errno == errno.EADDRINUSE and self.mode.custom_listen_port is None:
                    assert self.mode.custom_listen_host is None  # since [@ [listen_addr:]listen_port]
                    message += f"\nTry specifying a different port by using `--mode {self.mode.full_spec}@{port + 1}`."
                raise OSError(e.errno, message, e.filename) from e
            except:
                await self.report(state=ServerInstanceState.STOPPED, exception=sys.exc_info()[1])
                raise
            else:
                listen_addrs = tuple(s.getsockname() for s in self.server.sockets)
                self._listen_addrs = listen_addrs
                await self.report(state=ServerInstanceState.RUNNING)

        ctx.log.info(f"{self.log_desc} listening at {' and '.join(map(human.format_address, listen_addrs))}.")

    async def stop(self):
        async with self._lock:
            if self.server is None:
                return
            await self.report(state=ServerInstanceState.STOP_PENDING)
            try:
                self.server.close()
                await self.server.wait_closed()
            except:
                # don't fallback to RUNNING
                await self.report(state=ServerInstanceState.STOP_PENDING, exception=sys.exc_info()[1])
                raise
            else:
                self.server = None
                listen_addrs = self._listen_addrs
                self._listen_addrs = None
                await self.report(state=ServerInstanceState.STOPPED)

        ctx.log.info(f"Stopped {self.log_desc} at {' and '.join(map(human.format_address, listen_addrs))}.")

    @abstractmethod
    async def listen(self, host: str, port: int) -> asyncio.Server | udp.UdpServer:
        pass

    @property
    @abstractmethod
    def log_desc(self) -> str:
        pass

    @property
    def listen_addrs(self) -> tuple[Address, ...]:
        return self._listen_addrs


class TcpServerInstance(AsyncioServerInstance[M], metaclass=ABCMeta):

    @abstractmethod
    def make_top_layer(self, context: Context) -> Layer:
        pass

    async def handle_tcp_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        connection_id = (
            "tcp",
            writer.get_extra_info("peername"),
            writer.get_extra_info("sockname"),
        )
        handler = ProxyConnectionHandler(
            ctx.master, reader, writer, ctx.options, self.mode
        )
        handler.layer = self.make_top_layer(handler.layer.context)
        with self.manager.register_connection(connection_id, handler):
            await handler.handle_client()

    async def listen(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(
            self.handle_tcp_connection,
            host,
            port,
        )


class RegularInstance(TcpServerInstance[mode_specs.RegularMode]):
    log_desc = "HTTP(S) proxy"

    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.HttpProxy(context)


class UpstreamInstance(TcpServerInstance[mode_specs.UpstreamMode]):
    log_desc = "HTTP(S) proxy (upstream mode)"

    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.HttpUpstreamProxy(context)


class TransparentInstance(TcpServerInstance[mode_specs.TransparentMode]):
    log_desc = "Transparent proxy"

    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.TransparentProxy(context)


class ReverseInstance(TcpServerInstance[mode_specs.ReverseMode]):
    @property
    def log_desc(self) -> str:
        return f"Reverse proxy to {self.mode.data}"

    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.ReverseProxy(context)


class Socks5Instance(TcpServerInstance[mode_specs.Socks5Mode]):
    log_desc = "SOCKS v5 proxy"

    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.Socks5Proxy(context)


class UdpServerInstance(AsyncioServerInstance[M], metaclass=ABCMeta):

    @abstractmethod
    def make_top_layer(self, context: Context) -> Layer:
        pass

    @abstractmethod
    def make_connection_id(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        remote_addr: Address,
        local_addr: Address,
    ) -> tuple | None:
        pass

    async def listen(self, host: str, port: int) -> udp.UdpServer:
        return await udp.start_server(
            self.handle_udp_datagram,
            host,
            port,
            transparent=False
        )

    def handle_udp_datagram(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        remote_addr: Address,
        local_addr: Address,
    ) -> None:
        connection_id = self.make_connection_id(transport, data, remote_addr, local_addr)
        if connection_id is None:
            return
        if connection_id not in self.manager.connections:
            reader = udp.DatagramReader()
            writer = udp.DatagramWriter(transport, remote_addr, reader)
            handler = ProxyConnectionHandler(
                ctx.master, reader, writer, ctx.options, self.mode
            )
            handler.timeout_watchdog.CONNECTION_TIMEOUT = 20
            handler.layer = self.make_top_layer(handler.layer.context)

            # pre-register here - we may get datagrams before the task is executed.
            self.manager.connections[connection_id] = handler
            asyncio.create_task(self.handle_udp_connection(connection_id, handler))
        else:
            handler = self.manager.connections[connection_id]
            reader = cast(udp.DatagramReader, handler.transports[handler.client].reader)
        reader.feed_data(data, remote_addr)

    async def handle_udp_connection(self, connection_id: tuple, handler: ProxyConnectionHandler) -> None:
        with self.manager.register_connection(connection_id, handler):
            await handler.handle_client()


class DnsInstance(UdpServerInstance[mode_specs.DnsMode]):
    log_desc = "DNS server"

    def make_top_layer(self, context: Context) -> Layer:
        layer = layers.DNSLayer(context)
        layer.context.server.address = (self.mode.data or "resolve-local", 53)
        layer.context.server.transport_protocol = "udp"
        return layer

    def make_connection_id(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        remote_addr: Address,
        local_addr: Address,
    ) -> tuple | None:
        try:
            dns_id = struct.unpack_from("!H", data, 0)
        except struct.error:
            ctx.log.info(
                f"Invalid DNS datagram received from {human.format_address(remote_addr)}."
            )
            return None
        else:
            return ("udp", dns_id, remote_addr, local_addr)


class DtlsInstance(UdpServerInstance[mode_specs.DtlsMode]):
    log_desc = "DTLS server"

    def make_top_layer(self, context: Context) -> Layer:
        context.client.transport_protocol = "udp"
        layer = layers.ServerTLSLayer(context)
        layer.child_layer = layers.ClientTLSLayer(layer.context)
        layer.child_layer.child_layer = layers.UDPLayer(layer.context)
        layer.context.server.address = self.mode.address
        layer.context.server.transport_protocol = "udp"
        return layer

    def make_connection_id(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        remote_addr: Address,
        local_addr: Address,
    ) -> tuple | None:
        return ("dtls", remote_addr, local_addr)
