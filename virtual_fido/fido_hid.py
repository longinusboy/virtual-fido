"""FIDO HID interface.

The USB interface that carries CTAPHID traffic: two interrupt endpoints (IN
report poll + OUT report). Wraps a CTAPHIDServer-style delegate. Behavior is
unchanged from the original single-interface device — only the plumbing moved
into the multi-interface model.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from ._util import RequestBuffer
from .usb import (
    ATTR_INTERRUPT,
    DIR_IN,
    HID_REPORT_DESCRIPTOR,
    INTERFACE_CLASS_HID,
    EndpointSpec,
    USBDeviceDelegate,
    USBInterface,
    hid_descriptor,
)

logger = logging.getLogger("virtual_fido.usb.fido")


class FidoHIDInterface(USBInterface):
    interface_class = INTERFACE_CLASS_HID
    interface_subclass = 0
    interface_protocol = 0
    interface_string = None
    endpoint_specs = [
        EndpointSpec(is_in=True, attributes=ATTR_INTERRUPT, interval=255),   # report poll
        EndpointSpec(is_in=False, attributes=ATTR_INTERRUPT, interval=255),  # report out
    ]

    def __init__(self, delegate: USBDeviceDelegate) -> None:
        self._delegate = delegate
        self._buffer = RequestBuffer()
        delegate.set_response_handler(self._buffer.respond)

    def class_descriptors(self) -> bytes:
        return hid_descriptor(len(HID_REPORT_DESCRIPTOR))

    def report_descriptor(self) -> bytes:
        return HID_REPORT_DESCRIPTOR

    def handle_class_control(self, setup) -> Optional[bytes]:
        # SET_IDLE / SET_PROTOCOL etc. are no-ops for a virtual device.
        return None

    def handle_data(
        self,
        endpoint: int,
        direction: int,
        request_id: int,
        transfer_buffer: bytes,
        on_finish: Callable[[Optional[bytes]], None],
    ) -> None:
        if direction == DIR_IN:
            # Host polls for a HID report; leave pending until CTAPHID
            # produces one (no timeout NAK — see usb.py history).
            self._buffer.request(request_id, on_finish)
        else:
            # Host sent a CTAPHID packet. Handling may block on user approval,
            # so process off the URB loop; a bad packet must not kill the stack.
            logger.debug("FIDO OUT: %r", transfer_buffer)

            def process() -> None:
                try:
                    self._delegate.handle_message(transfer_buffer)
                except Exception:
                    logger.exception("Error handling FIDO report")

            threading.Thread(target=process, daemon=True).start()
            on_finish(None)

    def cancel_request(self, request_id: int) -> bool:
        return self._buffer.cancel_request(request_id)
