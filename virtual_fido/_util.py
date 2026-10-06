"""Cross-cutting helpers shared by the protocol layers.

Port of the Go util/ package. Most of it maps directly onto the standard
library (struct, logging, threading); only the pieces with real logic
survive here.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional


class ProtocolError(Exception):
    """Unrecoverable error while handling a protocol message.

    The Go original panics for these and recovers at the connection
    loop; we raise and catch at the same boundary.
    """


def utf16_encode(message: str) -> bytes:
    return message.encode("utf-16-le")


def cstring_to_str(data: bytes) -> str:
    """Decode a null-terminated byte string (util.CStringToString)."""
    i = data.find(b"\x00")
    if i < 0:
        raise ProtocolError("No null termination in C string")
    return data[:i].decode()


def pad(data: bytes, size: int) -> bytes:
    """Zero-pad (or truncate) to exactly `size` bytes (util.Pad)."""
    return data[:size] + b"\x00" * (size - len(data))


def set_timeout(seconds: float, f: Callable[[], None]) -> threading.Timer:
    """Run `f` once after `seconds` on a daemon timer thread (util.SetTimeout)."""
    timer = threading.Timer(seconds, f)
    timer.daemon = True
    timer.start()
    return timer


def start_recurring(interval: float, f: Callable[[], None]) -> Callable[[], None]:
    """Run `f` every `interval` seconds until the returned stop function is
    called (util.StartRecurringFunction)."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(interval):
            f()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return stop.set


class RequestBuffer:
    """Pairs asynchronous data requests with responses.

    Port of upstream util/request_buffer.go: the USB interrupt-IN endpoint requests
    data that may not exist yet; responses produced by the CTAPHID layer
    are buffered until a request arrives, and vice versa.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # dict preserves insertion order, so unlike Go's random map
        # iteration we always answer the oldest waiting request first.
        self._waiting: dict[int, Callable[[Optional[bytes]], None]] = {}
        self._responses: list[bytes] = []

    def request(self, request_id: int, callback: Callable[[Optional[bytes]], None]) -> bool:
        """Ask for data; called immediately if a response is queued."""
        with self._lock:
            if self._responses:
                response = self._responses.pop(0)
            else:
                self._waiting[request_id] = callback
                return False
        callback(response)
        return True

    def cancel_request(self, request_id: int) -> bool:
        with self._lock:
            return self._waiting.pop(request_id, None) is not None

    def respond(self, data: bytes) -> None:
        """Deliver data to the oldest waiting request, or queue it."""
        with self._lock:
            if self._waiting:
                request_id = next(iter(self._waiting))
                callback = self._waiting.pop(request_id)
            else:
                self._responses.append(data)
                return
        callback(data)
