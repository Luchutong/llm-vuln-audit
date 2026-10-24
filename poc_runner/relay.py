"""Loopback development bridge to the isolated runner; no application state or secrets."""
from __future__ import annotations

import asyncio
import contextlib
import logging

LOG = logging.getLogger("poc-runner-dev")


async def relay_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
    *,
    connect_timeout: float = 5.0,
    idle_timeout: float = 300.0,
) -> None:
    upstream_writer = None
    pumps: list[asyncio.Task] = []

    async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
        while True:
            data = await asyncio.wait_for(source.read(65536), timeout=idle_timeout)
            if not data:
                # A client may finish uploading before the runner sends its response.
                # Preserve this half-close rather than cancelling the return stream.
                if target.can_write_eof():
                    target.write_eof()
                    await asyncio.wait_for(target.drain(), timeout=idle_timeout)
                return
            target.write(data)
            await asyncio.wait_for(target.drain(), timeout=idle_timeout)

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(upstream_host, upstream_port), timeout=connect_timeout,
        )
        pumps = [asyncio.create_task(copy(reader, upstream_writer)),
                 asyncio.create_task(copy(upstream_reader, writer))]
        await asyncio.gather(*pumps)
    except (OSError, TimeoutError) as exc:
        # Never log forwarded bytes, headers, credentials or request paths.
        LOG.warning("Relay connection closed: %s", type(exc).__name__)
    finally:
        for pump in pumps:
            if not pump.done():
                pump.cancel()
        await asyncio.gather(*pumps, return_exceptions=True)
        streams = [stream for stream in (upstream_writer, writer) if stream is not None]
        for stream in streams:
            stream.close()
        for stream in streams:
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(stream.wait_closed(), timeout=connect_timeout)


async def serve() -> None:
    slots = asyncio.Semaphore(64)

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if slots.locked():
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            return
        async with slots:
            # The upstream is fixed; client input cannot select another destination.
            await relay_connection(reader, writer, "poc-runner", 8080)

    server = await asyncio.start_server(accept, "0.0.0.0", 8080)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    asyncio.run(serve())
