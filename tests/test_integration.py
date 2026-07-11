"""Full-stack integration: drive HID packets through the whole Python stack
(USBDevice -> CTAPHIDServer -> CTAP2/U2F -> DefaultFIDOClient), exactly the
path a real host would exercise after `usbip attach`.

This is the closest we get to end-to-end verification without a working
usbip client on this machine.
"""

import hashlib
import struct
import threading
import time

import cbor2

import virtual_fido
from virtual_fido import cose, crypto, ctap, ctap_hid, identities, u2f, usb
from virtual_fido.fido_client import DefaultFIDOClient


class AutoApproveMemorySupport:
    def __init__(self):
        self.data = None

    def approve_client_action(self, action, params):
        return True

    def save_data(self, data):
        self.data = data

    def retrieve_data(self):
        return self.data

    def passphrase(self):
        return "pw"


def build_stack():
    support = AutoApproveMemorySupport()
    ca_key = identities.create_ca_private_key()
    ca = identities.create_self_signed_ca(ca_key)
    client = DefaultFIDOClient(
        attestation_ca_certificate=ca,
        attestation_ca_private_key=ca_key,
        secret_encryption_key=hashlib.sha256(b"test").digest(),
        enable_pin=False,
        request_approver=support,
        data_saver=support,
    )
    ctap_server = ctap.CTAPServer(client)
    u2f_server = u2f.U2FServer(client)
    hid_server = ctap_hid.CTAPHIDServer(ctap_server, u2f_server)
    from virtual_fido.fido_hid import FidoHIDInterface

    device = usb.USBDevice([FidoHIDInterface(hid_server)])
    return client, device


# FIDO is the only interface here: EP1 IN (report poll), EP2 OUT (report in).
_FIDO_IN_EP = 1
_FIDO_OUT_EP = 2


class HostDriver:
    """Emulates the host: sends CTAPHID messages via the interrupt-IN
    endpoint and collects packets by polling the interrupt-OUT endpoint,
    exactly as the USB layer routes them.

    The USB RequestBuffer queues response packets when no poll is
    outstanding, so we send the request, then poll until the response
    message reassembles (or we run out of attempts)."""

    def __init__(self, device: usb.USBDevice):
        self._device = device
        self._packets: list[bytes] = []
        self._lock = threading.Lock()
        self._request_id = 1000

    def _on_packet(self, response):
        # Persistent callback: a packet may arrive synchronously (queued) or
        # later from the CTAP worker thread via a waiter we registered.
        if response is not None:
            with self._lock:
                self._packets.append(response)

    def _poll_once(self):
        self._request_id += 1
        self._device.handle_message(
            self._request_id, self._on_packet, _FIDO_IN_EP, usb.DIR_IN, b"\x00" * 8, b""
        )

    def send_message(self, channel_id: int, command: int, payload: bytes) -> bytes:
        # Each call fully drains its own response, so start clean — otherwise
        # reassembly could re-find a previous same-command response.
        with self._lock:
            self._packets.clear()
        for packet in ctap_hid.create_response_packets(channel_id, command, payload):
            self._device.handle_message(
                0, lambda r: None, _FIDO_OUT_EP, usb.DIR_OUT, b"\x00" * 8, packet
            )
        # Keep several interrupt-IN polls outstanding so the CTAPHID server
        # can deliver every response packet; CTAP handling runs on a worker
        # thread, so retry with small sleeps rather than assuming immediacy.
        for _ in range(400):
            for _ in range(8):
                self._poll_once()
            result = self._reassemble(channel_id, command)
            if result is not None:
                return result
            time.sleep(0.005)
        raise AssertionError("Response never fully reassembled")

    def _reassemble(self, channel_id, expected_command):
        payload = b""
        length = None
        with self._lock:
            packets = list(self._packets)
        for packet in packets:
            if int.from_bytes(packet[0:4], "little") != channel_id:
                continue
            command = packet[4]
            if command == ctap_hid.COMMAND_KEEPALIVE:
                continue
            if command & 0x80:  # initialization packet
                if command != expected_command:
                    continue
                length = int.from_bytes(packet[5:7], "big")
                payload = packet[7:]
            else:  # continuation
                payload += packet[5:]
            if length is not None and len(payload) >= length:
                return payload[:length]
        return None


def open_channel(driver: HostDriver) -> int:
    nonce = crypto.random_bytes(8)
    response = driver.send_message(ctap_hid.BROADCAST_CHANNEL, ctap_hid.COMMAND_INIT, nonce)
    assert response[:8] == nonce
    return struct.unpack("<I", response[8:12])[0]


def test_full_stack_ctap2_make_credential_and_get_assertion():
    client, device = build_stack()
    driver = HostDriver(device)
    channel_id = open_channel(driver)

    # MakeCredential
    make_args = {
        1: hashlib.sha256(b"client-data").digest(),
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01\x02", "displayName": "Alice", "name": "alice"},
        4: [{"type": "public-key", "alg": cose.ALGORITHM_ES256}],
        7: {"rk": True},
    }
    response = driver.send_message(
        channel_id,
        ctap_hid.COMMAND_CBOR,
        bytes([ctap.COMMAND_MAKE_CREDENTIAL]) + cbor2.dumps(make_args),
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    make_body = cbor2.loads(response[1:])
    assert make_body[1] == "packed"
    assert len(client.identities()) == 1

    # GetAssertion for the credential we just made
    client_data_hash = hashlib.sha256(b"login").digest()
    get_args = {1: "example.com", 2: client_data_hash, 5: {}}
    response = driver.send_message(
        channel_id,
        ctap_hid.COMMAND_CBOR,
        bytes([ctap.COMMAND_GET_ASSERTION]) + cbor2.dumps(get_args),
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    body = cbor2.loads(response[1:])
    auth_data, signature = body[2], body[3]
    credential = client.identities()[0]
    assert credential.private_key.public().verify(auth_data + client_data_hash, signature)


def test_full_stack_u2f_register_and_authenticate():
    client, device = build_stack()
    driver = HostDriver(device)
    channel_id = open_channel(driver)

    challenge = crypto.random_bytes(32)
    application = crypto.random_bytes(32)
    register_apdu = (
        bytes([0, u2f.COMMAND_REGISTER, 0, 0])
        + b"\x00"
        + (len(challenge + application)).to_bytes(2, "big")
        + challenge
        + application
    )
    response = driver.send_message(channel_id, ctap_hid.COMMAND_MSG, register_apdu)
    assert response[0] == 0x05
    assert int.from_bytes(response[-2:], "big") == u2f.SW_NO_ERROR

    encoded_public_key = response[1:66]
    public_key = crypto.decode_public_key(encoded_public_key)
    key_handle_length = response[66]
    key_handle = response[67 : 67 + key_handle_length]

    # Authenticate with the returned key handle
    new_challenge = crypto.random_bytes(32)
    auth_request = new_challenge + application + bytes([key_handle_length]) + key_handle
    auth_apdu = (
        bytes([0, u2f.COMMAND_AUTHENTICATE, u2f.AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN, 0])
        + b"\x00"
        + len(auth_request).to_bytes(2, "big")
        + auth_request
    )
    response = driver.send_message(channel_id, ctap_hid.COMMAND_MSG, auth_apdu)
    assert int.from_bytes(response[-2:], "big") == u2f.SW_NO_ERROR
    counter = response[1:5]
    signature = response[5:-2]
    signature_data = application + b"\x01" + counter + new_challenge
    assert crypto.verify_ecdsa(public_key, signature_data, signature)
