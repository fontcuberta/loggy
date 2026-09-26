import asyncio
import errno
import logging
import re

logger = logging.getLogger("loggy")

OCTET = re.compile(br"^(\d{1,6}) <")


def split_syslog_buffer(buf):
    lines = []
    while buf:
        match = OCTET.match(buf)
        if match:
            length = int(match.group(1))
            start = match.end() - 1
            if len(buf) < start + length:
                break
            frame = buf[start : start + length]
            buf = buf[start + length :]
            lines.extend(_decode_frame(frame))
            continue
        newline = buf.find(b"\n")
        if newline < 0:
            break
        lines.append(buf[:newline].decode("utf-8", errors="replace").rstrip("\r"))
        buf = buf[newline + 1 :]
    if len(buf) > 1_000_000:
        buf = buf[-1000:]
    return lines, buf


def _decode_frame(frame):
    text = frame.decode("utf-8", errors="replace").strip("\x00")
    parts = text.splitlines() or [text]
    return [part.rstrip("\r") for part in parts if part.strip()]


class _Datagram(asyncio.DatagramProtocol):
    def __init__(self, accept):
        self._accept = accept

    def datagram_received(self, data, addr):
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines() or [text]:
            if line.strip():
                self._accept(line.strip("\r"))


class SyslogServer:
    def __init__(self, on_line):
        self._on_line = on_line
        self.transport = None
        self.tcp_server = None
        self.port = None
        self.error = None
        self.received = 0

    @property
    def running(self):
        return self.transport is not None or self.tcp_server is not None

    async def start(self, port):
        await self.stop()
        self.error = None
        loop = asyncio.get_running_loop()
        try:
            self.tcp_server = await asyncio.start_server(self._handle_tcp, "127.0.0.1", int(port))
            sockets = self.tcp_server.sockets or []
            actual = sockets[0].getsockname()[1] if sockets else int(port)
            self.transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _Datagram(self._accept),
                local_addr=("127.0.0.1", actual),
            )
        except OSError as exc:
            await self.stop()
            self.port = None
            self.error = _bind_error(exc, port)
            return
        self.port = actual

    async def stop(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        if self.tcp_server is not None:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            self.tcp_server = None
        self.port = None

    async def restart(self, port):
        await self.start(port)

    def _accept(self, line):
        try:
            self._on_line(line)
        except Exception:
            logger.exception("No se pudo guardar una línea syslog")
            return
        self.received += 1

    async def _handle_tcp(self, reader, writer):
        buf = b""
        try:
            while True:
                chunk = await reader.read(65535)
                if not chunk:
                    break
                buf += chunk
                lines, buf = split_syslog_buffer(buf)
                for line in lines:
                    if line.strip():
                        self._accept(line)
        finally:
            if buf.strip():
                lines, _rest = split_syslog_buffer(buf + b"\n")
                for line in lines:
                    if line.strip():
                        self._accept(line)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _bind_error(exc, port):
    if exc.errno in (errno.EACCES, errno.EPERM):
        return "El puerto %s exige privilegios de administrador. Usa 5514 u otro puerto por encima de 1024." % port
    if exc.errno == errno.EADDRINUSE:
        return "El puerto %s ya está en uso en este equipo." % port
    return "No se pudo abrir el puerto %s en localhost." % port
