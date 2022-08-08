"""
This addon is responsible for starting/stopping the proxy server sockets/instances specified by the mode option.
"""
from __future__ import annotations

import asyncio
import collections
import inspect
import ipaddress
from contextlib import contextmanager
import sys
from typing import Any, Coroutine, Iterable, Iterator, Optional
import blinker

from wsproto.frame_protocol import Opcode

from mitmproxy import (
    command,
    ctx,
    exceptions,
    http,
    platform,
    tcp,
    websocket,
)
from mitmproxy.connection import Address
from mitmproxy.flow import Flow
from mitmproxy.proxy import events, mode_specs, server_hooks
from mitmproxy.proxy.layers.tcp import TcpMessageInjected
from mitmproxy.proxy.layers.websocket import WebSocketMessageInjected
from mitmproxy.proxy.mode_servers import ProxyConnectionHandler, ServerInstance, ServerInstanceState, ServerManager
from mitmproxy.utils import human


class Servers:
    def __init__(self, manager: ServerManager):
        self.changed = blinker.Signal()
        self._specs: set[mode_specs.ProxyMode] = set()
        self._instances: dict[mode_specs.ProxyMode, ServerInstance] = dict()
        self._lock = asyncio.Lock()
        self._manager = manager

    async def notify(
        self,
        added: set[ServerInstance] | None = None,
        updated: set[ServerInstance] | None = None,
        removed: set[ServerInstance] | None = None,
    ) -> None:
        if not added and not updated and not removed:
            return

        async def safe_start(instance: ServerInstance):
            try:
                await instance.start()
            except:
                ctx.log.error(str(sys.exc_info()[1]))

        # handle instance updates of orderly stopped instances that haven't been removed yet
        if updated:
            async with self._lock:
                for instance in updated.intersection(self._instances.values()):
                    if instance.state is ServerInstanceState.STOPPED and instance.exception is None:
                        if instance.mode in self._specs:
                            # restart the stopped instance, since its mode is still needed
                            asyncio.create_task(safe_start(instance))
                        else:
                            # remove the stopped instance, since its mode is no longer needed
                            del self._instances[instance.mode]
                            if removed is None:
                                removed = set()
                            removed.add(instance)

        # signal with blinker, but support async registrations
        coroutines = [
            ret
            for _, ret in self.changed.send(
                self._manager,
                added=set() if added is None else added,
                updated=set() if updated is None else updated,
                removed=set() if removed is None else removed,
            )
            if ret is not None and inspect.iscoroutine(ret)
        ]
        if coroutines:
            await asyncio.gather(*coroutines)

    async def setup(self, modes: Iterable[mode_specs.ProxyMode]) -> bool:
        tasks: list[Coroutine[Any, Any, None]] = list()
        added: set[ServerInstance] = set()
        removed: set[ServerInstance] = set()
        async with self._lock:
            self._specs = set(modes) if ctx.options.server else set()
            # go over all existing instances and remove valid ones from a copy of specs
            missing_specs = self._specs.copy()
            for spec, instance in self._instances.copy().items():
                if spec in self._specs:
                    # the instance's mode is still configured
                    if instance.state is ServerInstanceState.STOP_PENDING:
                        if instance.exception is None:
                            # it's still stopping, keep waiting and don't create a new instance
                            missing_specs.remove(spec)
                        else:
                            # stopping failed, remove the instance forcefully
                            del self._instances[spec]
                            removed.add(instance)
                    else:
                        # the instance is in a start(able) or running state, so don't create a new instance
                        missing_specs.remove(spec)
                        if instance.state is ServerInstanceState.STOPPED:
                            # try to start the instance (again)
                            tasks.append(instance.start())
                else:
                    # the instance is no longer configured
                    if instance.state is ServerInstanceState.STOPPED:
                        # it's stopped, so remove it immediately
                        del self._instances[spec]
                        removed.add(instance)
                    else:
                        # otherwise try to stop it (again) and remove it later
                        tasks.append(instance.stop())

            # create and start all missing modes
            for spec in missing_specs:
                instance = ServerInstance.make(spec, self._manager)
                self._instances[spec] = instance
                added.add(instance)
                tasks.append(instance.start())

        # we are out of the lock, notify listeners about the changes and wait for the tasks
        await self.notify(added=added, removed=removed)
        all_ok = True
        for ret in await asyncio.gather(*tasks, return_exceptions=True):
            if ret:
                all_ok = False
                ctx.log.error(str(ret))
        return all_ok

    def __len__(self) -> int:
        return len(self._instances)

    def __iter__(self) -> Iterator[ServerInstance]:
        return iter(self._instances.values())

    def __getitem__(self, mode: str | mode_specs.ProxyMode) -> ServerInstance:
        if isinstance(mode, str):
            mode = mode_specs.ProxyMode.parse(mode)
        return self._instances[mode]


class Proxyserver(ServerManager):
    """
    This addon runs the actual proxy server.
    """
    connections: dict[tuple, ProxyConnectionHandler]
    servers: Servers

    is_running: bool
    _connect_addr: Optional[Address] = None

    def __init__(self):
        self.connections = {}
        self.servers = Servers(self)
        self.is_running = False

    def __repr__(self):
        return f"Proxyserver({len(self.connections)} active conns)"

    async def update_instance(self, instance: ServerInstance):
        await self.servers.notify(updated={instance})

    @contextmanager
    def register_connection(self, connection_id: tuple, handler: ProxyConnectionHandler):
        self.connections[connection_id] = handler
        try:
            yield
        finally:
            del self.connections[connection_id]

    def load(self, loader):
        loader.add_option(
            "connection_strategy",
            str,
            "eager",
            "Determine when server connections should be established. When set to lazy, mitmproxy "
            "tries to defer establishing an upstream connection as long as possible. This makes it possible to "
            "use server replay while being offline. When set to eager, mitmproxy can detect protocols with "
            "server-side greetings, as well as accurately mirror TLS ALPN negotiation.",
            choices=("eager", "lazy"),
        )
        loader.add_option(
            "stream_large_bodies",
            Optional[str],
            None,
            """
            Stream data to the client if response body exceeds the given
            threshold. If streamed, the body will not be stored in any way.
            Understands k/m/g suffixes, i.e. 3m for 3 megabytes.
            """,
        )
        loader.add_option(
            "body_size_limit",
            Optional[str],
            None,
            """
            Byte size limit of HTTP request and response bodies. Understands
            k/m/g suffixes, i.e. 3m for 3 megabytes.
            """,
        )
        loader.add_option(
            "keep_host_header",
            bool,
            False,
            """
            Reverse Proxy: Keep the original host header instead of rewriting it
            to the reverse proxy target.
            """,
        )
        loader.add_option(
            "proxy_debug",
            bool,
            False,
            "Enable debug logs in the proxy core.",
        )
        loader.add_option(
            "normalize_outbound_headers",
            bool,
            True,
            """
            Normalize outgoing HTTP/2 header names, but emit a warning when doing so.
            HTTP/2 does not allow uppercase header names. This option makes sure that HTTP/2 headers set
            in custom scripts are lowercased before they are sent.
            """,
        )
        loader.add_option(
            "validate_inbound_headers",
            bool,
            True,
            """
            Make sure that incoming HTTP requests are not malformed.
            Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.
            """,
        )
        loader.add_option(
            "connect_addr",
            Optional[str],
            None,
            """Set the local IP address that mitmproxy should use when connecting to upstream servers.""",
        )

    def running(self):
        self.is_running = True

    def configure(self, updated):
        if "stream_large_bodies" in updated:
            try:
                human.parse_size(ctx.options.stream_large_bodies)
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid stream_large_bodies specification: "
                    f"{ctx.options.stream_large_bodies}"
                )
        if "body_size_limit" in updated:
            try:
                human.parse_size(ctx.options.body_size_limit)
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid body_size_limit specification: "
                    f"{ctx.options.body_size_limit}"
                )
        if "connect_addr" in updated:
            try:
                if ctx.options.connect_addr:
                    self._connect_addr = str(ipaddress.ip_address(ctx.options.connect_addr)), 0
                else:
                    self._connect_addr = None
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid value for connect_addr: {ctx.options.connect_addr!r}. Specify a valid IP address."
                )
        if "mode" in updated or "server" in updated:
            # Make sure that all modes are syntactically valid...
            modes: list[mode_specs.ProxyMode] = []
            for mode in ctx.options.mode:
                try:
                    modes.append(
                        mode_specs.ProxyMode.parse(mode)
                    )
                except ValueError as e:
                    raise exceptions.OptionsError(f"Invalid proxy mode specification: {mode} ({e})")

            # ...and don't listen on the same address.
            listen_addrs = [
                (
                    m.listen_host(ctx.options.listen_host),
                    m.listen_port(ctx.options.listen_port),
                    m.transport_protocol
                )
                for m in modes
            ]
            if len(set(listen_addrs)) != len(listen_addrs):
                (host, port, _) = collections.Counter(listen_addrs).most_common(1)[0][0]
                dup_addr = human.format_address((host or "0.0.0.0", port))
                raise exceptions.OptionsError(f"Cannot spawn multiple servers on the same address: {dup_addr}")

            if ctx.options.mode and not ctx.master.addons.get("nextlayer"):
                ctx.log.warn("Warning: Running proxyserver without nextlayer addon!")
            if any(isinstance(m, mode_specs.TransparentMode) for m in modes):
                if platform.original_addr:
                    platform.init_transparent_mode()
                else:
                    raise exceptions.OptionsError("Transparent mode not supported on this platform.")

            if self.is_running:
                asyncio.create_task(self.servers.setup(modes))

    async def setup_servers(self) -> bool:
        return await self.servers.setup(map(mode_specs.ProxyMode.parse, ctx.options.mode))

    def listen_addrs(self) -> list[Address]:
        return [
            addr
            for server in self.servers
            for addr in server.listen_addrs
        ]

    def inject_event(self, event: events.MessageInjected):
        connection_id = (
            "tcp",
            event.flow.client_conn.peername,
            event.flow.client_conn.sockname,
        )
        if connection_id not in self.connections:
            raise ValueError("Flow is not from a live connection.")
        self.connections[connection_id].server_event(event)

    @command.command("inject.websocket")
    def inject_websocket(
        self, flow: Flow, to_client: bool, message: bytes, is_text: bool = True
    ):
        if not isinstance(flow, http.HTTPFlow) or not flow.websocket:
            ctx.log.warn("Cannot inject WebSocket messages into non-WebSocket flows.")

        msg = websocket.WebSocketMessage(
            Opcode.TEXT if is_text else Opcode.BINARY, not to_client, message
        )
        event = WebSocketMessageInjected(flow, msg)
        try:
            self.inject_event(event)
        except ValueError as e:
            ctx.log.warn(str(e))

    @command.command("inject.tcp")
    def inject_tcp(self, flow: Flow, to_client: bool, message: bytes):
        if not isinstance(flow, tcp.TCPFlow):
            ctx.log.warn("Cannot inject TCP messages into non-TCP flows.")

        event = TcpMessageInjected(flow, tcp.TCPMessage(not to_client, message))
        try:
            self.inject_event(event)
        except ValueError as e:
            ctx.log.warn(str(e))

    def server_connect(self, data: server_hooks.ServerConnectionHookData):
        if data.server.sockname is None:
            data.server.sockname = self._connect_addr

        # Prevent mitmproxy from recursively connecting to itself.
        assert data.server.address
        connect_host, connect_port, *_ = data.server.address

        for server in self.servers:
            for listen_host, listen_port, *_ in server.listen_addrs:
                self_connect = (
                    connect_port == listen_port
                    and connect_host in (
                        "localhost",
                        "127.0.0.1",
                        "::1",
                        listen_host
                    )
                    and server.mode.transport_protocol == data.server.transport_protocol
                )
                if self_connect:
                    data.server.error = (
                        "Request destination unknown. "
                        "Unable to figure out where this request should be forwarded to."
                    )
                    return
