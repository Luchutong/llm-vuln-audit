"""Offline TCP relay contracts; all listeners use temporary local ports."""
from __future__ import annotations

import asyncio
import importlib.util
from contextlib import asynccontextmanager
from pathlib import Path

import pytest


@pytest.fixture
def relay_module():
    source = Path(__file__).resolve().parents[2] / "poc_runner" / "relay.py"
    spec = importlib.util.spec_from_file_location("poc_dev_relay_test_subject", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@asynccontextmanager
async def listener(handler, *, port=0):
    active = set()
    failures = []

    def accept(reader, writer):
        task = asyncio.create_task(handler(reader, writer))
        active.add(task)

        def done(completed):
            active.discard(completed)
            if not completed.cancelled() and completed.exception() is not None:
                failures.append(completed.exception())

        task.add_done_callback(done)

    server = await asyncio.start_server(accept, "127.0.0.1", port)
    address = server.sockets[0].getsockname()
    try:
        yield address[0], address[1]
    finally:
        server.close()
        await server.wait_closed()
        if active:
            remaining = list(active)
            for task in remaining:
                task.cancel()
            await asyncio.gather(*remaining, return_exceptions=True)
        assert not failures, failures


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def echo(reader, writer):
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    finally:
        await close_writer(writer)


def test_large_concurrent_connections_keep_bytes_and_clients_separate(relay_module):
    async def scenario():
        async with listener(echo) as upstream:
            async def forward(reader, writer):
                await relay_module.relay_connection(reader, writer, *upstream)

            async with listener(forward) as address:
                async def client(identity):
                    payload = bytes([identity]) + bytes(range(256)) * 4096 + bytes([identity])
                    reader, writer = await asyncio.open_connection(*address)
                    try:
                        async def send():
                            for offset in range(0, len(payload), 32768):
                                writer.write(payload[offset:offset + 32768])
                                await writer.drain()
                            writer.write_eof()

                        sent = asyncio.create_task(send())
                        received = await reader.read()
                        await sent
                        assert received == payload
                    finally:
                        await close_writer(writer)

                await asyncio.wait_for(asyncio.gather(*(client(i) for i in range(4))), 10)

    asyncio.run(scenario())


def test_client_half_close_keeps_delayed_response_readable(relay_module):
    async def scenario():
        received = []
        response = b"response-after-request-eof:" + bytes(range(256)) * 1024

        async def respond_after_eof(reader, writer):
            try:
                received.append(await reader.read())
                await asyncio.sleep(0.05)
                writer.write(response)
                await writer.drain()
            finally:
                await close_writer(writer)

        async with listener(respond_after_eof) as upstream:
            async def forward(reader, writer):
                await relay_module.relay_connection(reader, writer, *upstream)

            async with listener(forward) as address:
                reader, writer = await asyncio.open_connection(*address)
                try:
                    writer.write(b"request completed")
                    await writer.drain()
                    writer.write_eof()
                    assert await asyncio.wait_for(reader.read(), 3) == response
                    assert received == [b"request completed"]
                finally:
                    await close_writer(writer)

    asyncio.run(scenario())


def test_idle_connections_close_and_active_connections_remain_usable(relay_module):
    async def scenario():
        async with listener(echo) as upstream:
            async def forward(reader, writer):
                await relay_module.relay_connection(reader, writer, *upstream, idle_timeout=0.3)

            async with listener(forward) as address:
                reader, writer = await asyncio.open_connection(*address)
                try:
                    # Total duration exceeds idle_timeout; traffic must reset the deadline.
                    for _ in range(5):
                        writer.write(b"still active")
                        await writer.drain()
                        assert await asyncio.wait_for(reader.readexactly(12), 1) == b"still active"
                        await asyncio.sleep(0.1)
                    assert await asyncio.wait_for(reader.read(), 2) == b""
                finally:
                    await close_writer(writer)

    asyncio.run(scenario())


def test_upstream_failure_recovers_and_http_auth_is_forwarded_unchanged(relay_module):
    async def scenario():
        # Obtain an unused local port without depending on any existing service.
        async with listener(echo) as unused:
            upstream = unused
        request = (
            b"POST /v1/contexts HTTP/1.1\r\nHost: test-runner\r\n"
            b"Authorization: Bearer local-test-only-token\r\n"
            b"Content-Type: application/json\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\n{}"
        )
        response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
        seen = []

        async def http_upstream(reader, writer):
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                body = await reader.readexactly(2)
                seen.append(headers + body)
                writer.write(response)
                await writer.drain()
            finally:
                await close_writer(writer)

        async def forward(reader, writer):
            await relay_module.relay_connection(
                reader, writer, *upstream, connect_timeout=0.2, idle_timeout=1,
            )

        async with listener(forward) as address:
            reader, writer = await asyncio.open_connection(*address)
            try:
                try:
                    assert await asyncio.wait_for(reader.read(), 2) == b""
                except ConnectionResetError:
                    pass
            finally:
                await close_writer(writer)

            # The same relay listener must accept a new connection after its upstream recovers.
            async with listener(http_upstream, port=upstream[1]):
                reader, writer = await asyncio.open_connection(*address)
                try:
                    writer.write(request)
                    await writer.drain()
                    assert await asyncio.wait_for(reader.read(), 3) == response
                    assert seen == [request]
                finally:
                    await close_writer(writer)

    asyncio.run(scenario())
