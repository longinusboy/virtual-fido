"""Local control channel over a Unix domain socket.

Lets a separate CLI invocation drive a running server — e.g. `otp type`
triggers the running device to "type" a one-time password, standing in for a
YubiKey's physical button. Line protocol: request `command arg...\n`, response
`ok [detail]\n` or `error: message\n`. The socket is created with 0600
permissions; anyone who can open it can trigger actions, so keep it local.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Callable

logger = logging.getLogger("virtual_fido.control")

# command name -> handler(args: list[str]) -> detail string
Handler = Callable[[list], str]


class ControlServer:
    def __init__(self, path: str, handlers: dict[str, Handler]) -> None:
        self._path = path
        self._handlers = handlers

    def start(self) -> None:
        try:
            os.unlink(self._path)  # clear a stale socket from a previous run
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self._path)
        os.chmod(self._path, 0o600)
        sock.listen()
        logger.info("Control socket listening on %s", self._path)
        threading.Thread(target=self._accept_loop, args=(sock,), daemon=True).start()

    def _accept_loop(self, sock: socket.socket) -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            line = conn.makefile("r").readline().strip()
            if not line:
                return
            parts = line.split()
            command, args = parts[0], parts[1:]
            handler = self._handlers.get(command)
            if handler is None:
                conn.sendall(b"error: unknown command\n")
                return
            try:
                detail = handler(args)
                conn.sendall(f"ok {detail}\n".encode())
            except Exception as err:  # report back rather than crash the server
                logger.warning("Control command %r failed: %s", command, err)
                conn.sendall(f"error: {err}\n".encode())


def send_command(path: str, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(path)
        sock.sendall((command + "\n").encode())
        return sock.makefile("r").readline().strip()
