# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
"""Host side of the smart-core protocol (PROTOCOL.md), for asyncio.

No Home Assistant imports. Serial needs pyserial; TCP and BLE need
`cryptography` (secure sessions: Noise_XX_25519_ChaChaPoly_BLAKE2b); BLE
also needs `bleak`. The siakinnik-home integration is built on this.

    me = HostIdentity.load_or_create(path)
    dev = await connect("serial:COM5", me)          # USB: plain, trusted
    await dev.pair(me)                              # the device now trusts this host
    await dev.close()
    dev = await connect("tcp:192.168.0.184", me)    # network: encrypted, paired hosts only
    await dev.set({"light.brightness": 80, "light.color": (255, 0, 0)})
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import contextlib
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import threading
from typing import Any

PROTO_VERSION = 2

HELLO, DESCRIBE, GET, SET, PING, PAIR, UNPAIR = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
OTA_BEGIN, OTA_DATA, OTA_END = 0x08, 0x09, 0x0A
MANIFEST_LEN = 212
OTA_WINDOW = 8  # OTA_DATA requests in flight
INFO_HAS_KEY, INFO_OTA = 0x01, 0x02
INFO, PROP, VALUES, ACK, EVENT, PONG, ERROR = 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xEE

T_BOOL, T_U8, T_U16, T_I32, T_ENUM, T_RGB, T_STR, T_ACTION = range(1, 9)
F_READ, F_WRITE, F_PERSIST, F_SECRET, F_LOCAL = 0x01, 0x02, 0x04, 0x08, 0x10
ALL = 0xFF

ERRORS = {
    1: "unknown message type",
    2: "bad length",
    3: "unknown property",
    4: "value out of range",
    5: "read-only property",
    6: "forbidden on this transport",
    7: "unsupported protocol version",
    8: "the device's list of paired hosts is full",
    9: "image refused: not signed with the device's key, another model, or older than the installed firmware",
    10: "another host is updating the device",
    11: "the device couldn't store the image",
}

# frame kinds on an untrusted (secure) session
K_HS1, K_HS2, K_HS3, K_DATA, K_REJECT = 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
REJECTS = {
    1: "this host is not paired with the device",
    2: "pairing conflict: another host tried to pair in the same window",
    3: "the device's list of paired hosts is full",
    4: "handshake failed",
    5: "handshake timed out",
}
REJECT_NOT_PAIRED = 1

# smart-core over BLE: a GATT service with an RX (write) and a TX (notify) characteristic
BLE_SERVICE_UUID = "5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0001"
BLE_RX_UUID = "5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0002"
BLE_TX_UUID = "5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0003"
BLE_SCAN_TIMEOUT = 10.0

REQUEST_TIMEOUT = 3.0
# Connecting includes resolving the name: a .local name over mDNS takes
# several seconds on Windows.
CONNECT_TIMEOUT = 10.0
DEFAULT_TCP_PORT = 7531
BAUDRATE = 115200  # ignored by native USB, used by real UARTs
# Opening a serial port can reboot the board (USB-UART bridges wire DTR/RTS
# to reset/boot pins), so HELLO is repeated for this long before giving up.
SERIAL_HELLO_TIMEOUT = 15.0
HELLO_RETRY = 0.5


# ---------- framing ----------

def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def cobs_encode(data: bytes) -> bytes:
    out = bytearray([0])
    code_idx, code = 0, 1
    for b in data:
        if b == 0:
            out[code_idx] = code
            code_idx, code = len(out), 1
            out.append(0)
        else:
            out.append(b)
            code += 1
            if code == 0xFF:
                out[code_idx] = code
                code_idx, code = len(out), 1
                out.append(0)
    out[code_idx] = code
    return bytes(out)


def cobs_decode(data: bytes) -> bytes | None:
    out = bytearray()
    i = 0
    while i < len(data):
        code = data[i]
        i += 1
        if code == 0 or i + code - 1 > len(data):
            return None
        out += data[i : i + code - 1]
        i += code - 1
        if code != 0xFF and i < len(data):
            out.append(0)
    return bytes(out)


def frame(body: bytes) -> bytes:
    return b"\x00" + cobs_encode(body) + b"\x00"


def build_packet(msg_type: int, seq: int, payload: bytes = b"") -> bytes:
    """A plain (trusted session) packet: TYPE SEQ PAYLOAD CRC16, framed."""
    raw = bytes([msg_type, seq]) + payload
    return frame(raw + struct.pack("<H", crc16(raw)))


class FrameParser:
    """Splits a byte stream into frame bodies (COBS-decoded); drops anything malformed."""

    def __init__(self, max_len: int = 4096) -> None:
        self._buf = bytearray()
        self._max = max_len

    def feed(self, data: bytes) -> list[bytes]:
        bodies = []
        for b in data:
            if b:
                if len(self._buf) <= self._max:
                    self._buf.append(b)
                continue
            body = cobs_decode(bytes(self._buf)) if 0 < len(self._buf) <= self._max else None
            self._buf.clear()
            if body:
                bodies.append(body)
        return bodies


def parse_plain(body: bytes) -> tuple[int, int, bytes] | None:
    """(type, seq, payload) of a plain packet, or None if the CRC is wrong (log noise)."""
    if len(body) < 4 or crc16(body[:-2]) != struct.unpack("<H", body[-2:])[0]:
        return None
    return body[0], body[1], body[2:-2]


class PacketParser:
    """Plain packets only: splits a stream into (type, seq, payload)."""

    def __init__(self, max_len: int = 4096) -> None:
        self._frames = FrameParser(max_len)

    def feed(self, data: bytes) -> list[tuple[int, int, bytes]]:
        return [p for p in map(parse_plain, self._frames.feed(data)) if p]


# ---------- errors ----------

class SmartError(Exception):
    """The device rejected a request, or the link failed."""

    def __init__(self, message: str, code: int | None = None, prop: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.prop = prop


class RejectedError(SmartError):
    """The device refused the secure session (code: see REJECTS)."""


# ---------- Noise_XX_25519_ChaChaPoly_BLAKE2b, initiator side ----------

PROLOGUE = b"smart-core/2"
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2b"
HASHLEN = 64


def _x25519_public(secret: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(secret: bytes, public: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    shared = X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))
    if shared == bytes(32):
        raise SmartError("handshake failed: low-order key")
    return shared


def _hash(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=HASHLEN).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2b).digest()


def _hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    temp = _hmac(ck, ikm)
    out1 = _hmac(temp, b"\x01")
    return out1, _hmac(temp, out1 + b"\x02")


class CipherState:
    """ChaCha20-Poly1305 with Noise nonces (32 zero bits + 64-bit little-endian counter)."""

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key
        self.n = 0

    def _aead(self):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        return ChaCha20Poly1305(self.key)

    def _nonce(self) -> bytes:
        return b"\x00" * 4 + self.n.to_bytes(8, "little")

    def encrypt(self, plain: bytes, ad: bytes = b"") -> bytes:
        if self.key is None:
            return plain
        out = self._aead().encrypt(self._nonce(), plain, ad)
        self.n += 1
        return out

    def decrypt(self, cipher: bytes, ad: bytes = b"") -> bytes:
        if self.key is None:
            return cipher
        from cryptography.exceptions import InvalidTag

        try:
            out = self._aead().decrypt(self._nonce(), cipher, ad)
        except InvalidTag:
            raise SmartError("decryption failed: the session is broken or tampered with") from None
        self.n += 1
        return out


class NoiseXXInitiator:
    """The host's half of the handshake. Each step is a method; then send/recv."""

    def __init__(self, static_secret: bytes, prologue: bytes = PROLOGUE, ephemeral: bytes | None = None) -> None:
        self.s = static_secret
        self.s_pub = _x25519_public(static_secret)
        self.e = ephemeral if ephemeral is not None else os.urandom(32)
        self.e_pub = _x25519_public(self.e)
        self.h = NOISE_NAME.ljust(HASHLEN, b"\x00")
        self.ck = self.h
        self.cs = CipherState()
        self.rs: bytes | None = None
        self.re: bytes | None = None
        self._mix_hash(prologue)

    def _mix_hash(self, data: bytes) -> None:
        self.h = _hash(self.h + data)

    def _mix_key(self, ikm: bytes) -> None:
        self.ck, temp_k = _hkdf2(self.ck, ikm)
        self.cs = CipherState(temp_k[:32])

    def _encrypt_and_hash(self, plain: bytes) -> bytes:
        cipher = self.cs.encrypt(plain, self.h)
        self._mix_hash(cipher)
        return cipher

    def _decrypt_and_hash(self, cipher: bytes) -> bytes:
        plain = self.cs.decrypt(cipher, self.h)
        self._mix_hash(cipher)
        return plain

    def write1(self, payload: bytes = b"") -> bytes:
        """-> e"""
        self._mix_hash(self.e_pub)
        return self.e_pub + self._encrypt_and_hash(payload)

    def read2(self, msg: bytes) -> bytes:
        """<- e, ee, s, es. Afterwards `rs` is the responder's static key."""
        if len(msg) < 96:
            raise SmartError("handshake failed: message 2 too short")
        self.re = msg[:32]
        self._mix_hash(self.re)
        self._mix_key(_dh(self.e, self.re))
        self.rs = self._decrypt_and_hash(msg[32:80])
        self._mix_key(_dh(self.e, self.rs))
        return self._decrypt_and_hash(msg[80:])

    def write3(self, payload: bytes = b"") -> tuple[bytes, CipherState, CipherState]:
        """-> s, se. Returns the message and the (send, receive) cipher states."""
        out = self._encrypt_and_hash(self.s_pub)
        self._mix_key(_dh(self.s, self.re))
        out += self._encrypt_and_hash(payload)
        k1, k2 = _hkdf2(self.ck, b"")
        return out, CipherState(k1[:32]), CipherState(k2[:32])


# ---------- host identity ----------

@dataclass
class HostIdentity:
    """This host's static key and the devices it has paired with (device id -> key)."""

    secret: bytes
    devices: dict[str, bytes] = field(default_factory=dict)
    path: Path | None = None

    @property
    def public(self) -> bytes:
        return _x25519_public(self.secret)

    @classmethod
    def create(cls, path: Path | None = None) -> HostIdentity:
        return cls(os.urandom(32), {}, path)

    @classmethod
    def load_or_create(cls, path: str | Path) -> HostIdentity:
        path = Path(path)
        if path.exists():
            data = json.loads(path.read_text())
            devices = {k: bytes.fromhex(v) for k, v in data.get("devices", {}).items()}
            return cls(bytes.fromhex(data["secret"]), devices, path)
        me = cls.create(path)
        me.save()
        return me

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"secret": self.secret.hex(), "devices": {k: v.hex() for k, v in self.devices.items()}}
        # the secret key: readable by this user only
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)

    def knows(self, device_key: bytes) -> bool:
        return device_key in self.devices.values()

    def remember(self, device_id: str, device_key: bytes) -> None:
        self.devices[device_id] = device_key
        self.save()

    def forget(self, device_id: str) -> None:
        if self.devices.pop(device_id, None) is not None:
            self.save()


def fingerprint(key: bytes) -> str:
    """Short, readable form of a public key, for people comparing keys."""
    digest = hashlib.blake2b(key, digest_size=8).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


# ---------- descriptions and values ----------

@dataclass(frozen=True)
class DeviceInfo:
    proto: int
    prop_count: int
    model_id: int
    device_id: str
    model: str
    firmware: str
    public_key: bytes | None = None
    max_payload: int = 240
    ota: bool = False  # takes signed firmware updates


@dataclass(frozen=True)
class Prop:
    id: int
    type: int
    flags: int
    name: str
    min: int | None = None
    max: int | None = None
    options: tuple[str, ...] = ()
    max_len: int | None = None

    @property
    def readable(self) -> bool:
        return bool(self.flags & F_READ) and not self.flags & F_SECRET and self.type != T_ACTION

    @property
    def writable(self) -> bool:
        return bool(self.flags & F_WRITE)

    @property
    def group(self) -> str:
        """`light` for `light.power`; empty for names without a dot."""
        return self.name.split(".", 1)[0] if "." in self.name else ""

    def encode(self, value) -> bytes:
        t = self.type
        if t == T_BOOL:
            return bytes([1 if value else 0])
        if t == T_ENUM:
            if isinstance(value, str):
                value = self.options.index(value)
            return bytes([value])
        if t == T_U8:
            return bytes([value])
        if t == T_U16:
            return struct.pack("<H", value)
        if t == T_I32:
            return struct.pack("<i", value)
        if t == T_RGB:
            return bytes(value)
        if t == T_STR:
            raw = value.encode()
            return bytes([len(raw)]) + raw
        if t == T_ACTION:
            return b""
        raise SmartError(f"{self.name}: unknown type {t}")

    def decode(self, data: bytes, pos: int):
        """Read one value at `pos`; return (value, new pos)."""
        t = self.type
        if t == T_BOOL:
            return bool(data[pos]), pos + 1
        if t in (T_U8, T_ENUM):
            return data[pos], pos + 1
        if t == T_U16:
            return struct.unpack_from("<H", data, pos)[0], pos + 2
        if t == T_I32:
            return struct.unpack_from("<i", data, pos)[0], pos + 4
        if t == T_RGB:
            return tuple(data[pos : pos + 3]), pos + 3
        if t == T_STR:
            n = data[pos]
            return data[pos + 1 : pos + 1 + n].decode(errors="replace"), pos + 1 + n
        if t == T_ACTION:
            return None, pos
        raise SmartError(f"{self.name}: unknown type {t}")


def _read_str(data: bytes, pos: int) -> tuple[str, int]:
    n = data[pos]
    return data[pos + 1 : pos + 1 + n].decode(errors="replace"), pos + 1 + n


def parse_info(p: bytes) -> DeviceInfo:
    proto, count, model_id = p[0], p[1], struct.unpack_from("<H", p, 2)[0]
    device_id, pos = _read_str(p, 4)
    model, pos = _read_str(p, pos)
    firmware, pos = _read_str(p, pos)
    max_payload, flags = 240, 0
    if len(p) - pos >= 3:
        max_payload, flags = struct.unpack_from("<HB", p, pos)
        pos += 3
    key = p[pos : pos + 32] if flags & INFO_HAS_KEY and len(p) - pos >= 32 else None
    return DeviceInfo(proto, count, model_id, device_id, model, firmware, key, max_payload, bool(flags & INFO_OTA))


def parse_prop(p: bytes) -> Prop:
    pid, ptype, flags = p[0], p[1], p[2]
    name, pos = _read_str(p, 3)
    kw: dict = {}
    if ptype == T_U8:
        kw = {"min": p[pos], "max": p[pos + 1]}
    elif ptype == T_U16:
        lo, hi = struct.unpack_from("<HH", p, pos)
        kw = {"min": lo, "max": hi}
    elif ptype == T_I32:
        lo, hi = struct.unpack_from("<ii", p, pos)
        kw = {"min": lo, "max": hi}
    elif ptype == T_ENUM:
        count = p[pos]
        pos += 1
        options = []
        for _ in range(count):
            opt, pos = _read_str(p, pos)
            options.append(opt)
        kw = {"options": tuple(options)}
    elif ptype == T_STR:
        kw = {"max_len": p[pos]}
    return Prop(pid, ptype, flags, name, **kw)


# ---------- serial transport ----------

class _SerialWriter:
    """The part of asyncio.StreamWriter that SmartDevice uses, over pyserial."""

    def __init__(self, port, reader_thread: threading.Thread) -> None:
        self._port = port
        self._thread = reader_thread

    def write(self, data: bytes) -> None:
        self._port.write(data)  # small packets: the OS buffer takes them at once

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._port.cancel_read()
        self._port.close()

    async def wait_closed(self) -> None:
        await asyncio.get_running_loop().run_in_executor(None, self._thread.join, 2.0)


async def open_serial(path: str, baudrate: int = BAUDRATE) -> tuple[asyncio.StreamReader, _SerialWriter]:
    """Open a serial port with DTR and RTS held low.

    On boards with a USB-UART bridge (CH340, CP210x) these lines drive the
    reset and boot pins, and pyserial would otherwise assert them on open.
    A thread reads the port and feeds an asyncio.StreamReader.
    """
    import serial  # optional dependency: only serial targets need it

    port = serial.Serial()
    port.port = path
    port.baudrate = baudrate
    port.timeout = 0.2
    port.write_timeout = REQUEST_TIMEOUT
    port.dtr = False  # applied by open(), before the line ever goes high
    port.rts = False
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, port.open)

    reader = asyncio.StreamReader()

    def pump() -> None:
        try:
            while port.is_open:
                data = port.read(max(1, port.in_waiting))
                if data:
                    loop.call_soon_threadsafe(reader.feed_data, data)
        except Exception as err:  # noqa: BLE001 - unplugged, closed, ...
            if port.is_open:
                loop.call_soon_threadsafe(reader.set_exception, SmartError(f"serial: {err}"))
                return
        loop.call_soon_threadsafe(reader.feed_eof)

    thread = threading.Thread(target=pump, name=f"smart-serial-{path}", daemon=True)
    thread.start()
    return reader, _SerialWriter(port, thread)


# ---------- BLE transport ----------

class _BleWriter:
    """The part of asyncio.StreamWriter that SmartDevice uses, over a GATT
    characteristic: write() queues, drain() sends in MTU-sized pieces."""

    def __init__(self, client) -> None:
        self._client = client
        self._buf = bytearray()
        self._lock = asyncio.Lock()

    def write(self, data: bytes) -> None:
        self._buf += data

    async def drain(self) -> None:
        async with self._lock:
            chunk = max(20, self._client.mtu_size - 3)
            while self._buf:
                piece, self._buf = bytes(self._buf[:chunk]), self._buf[chunk:]
                await self._client.write_gatt_char(BLE_RX_UUID, piece, response=True)

    def close(self) -> None:
        self._closing = asyncio.ensure_future(self._client.disconnect())

    async def wait_closed(self) -> None:
        with contextlib.suppress(Exception):
            await self._closing


def _ble_error(err: Exception) -> SmartError:
    """Bluetooth trouble (radio off, no adapter, ...) as a readable SmartError."""
    text = str(err.args[0]) if getattr(err, "args", None) else str(err)
    return SmartError(f"Bluetooth: {text}")


async def scan_ble(timeout: float = BLE_SCAN_TIMEOUT) -> list[tuple[str, str, int]]:
    """Devices advertising smart-core over BLE (they do while pairing): (name, address, rssi)."""
    from bleak import BleakScanner
    from bleak.exc import BleakError

    try:
        found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    except BleakError as err:
        raise _ble_error(err) from None
    out = []
    for device, adv in found.values():
        if BLE_SERVICE_UUID in [u.lower() for u in adv.service_uuids]:
            out.append((adv.local_name or device.name or "?", device.address, adv.rssi))
    return sorted(out, key=lambda d: -d[2])


async def open_ble(name_or_address: str, timeout: float = BLE_SCAN_TIMEOUT):
    """Connect to a device by its BLE name ("LumenC3-62B2") or address."""
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError

    try:
        return await _open_ble(BleakClient, BleakScanner, name_or_address, timeout)
    except BleakError as err:
        raise _ble_error(err) from None


async def _open_ble(BleakClient, BleakScanner, name_or_address: str, timeout: float):
    want = name_or_address.lower()

    def match(device, adv) -> bool:
        names = {(adv.local_name or "").lower(), (device.name or "").lower()}
        return want in names or device.address.lower() == want

    device = await BleakScanner.find_device_by_filter(match, timeout=timeout)
    if device is None:
        raise SmartError(f"no BLE device {name_or_address!r} found: is its pairing window open?")

    reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()
    client = BleakClient(device, disconnected_callback=lambda _: loop.call_soon_threadsafe(reader.feed_eof))
    await client.connect()
    try:
        await client.start_notify(BLE_TX_UUID, lambda _, data: reader.feed_data(bytes(data)))
    except BaseException:
        await client.disconnect()
        raise
    return reader, _BleWriter(client)


# ---------- device ----------

@dataclass
class SmartDevice:
    """A connected device: its description, current values and a request API.

    A trusted transport (serial/USB) speaks plain packets. Anything else
    (TCP) runs a Noise handshake first: see connect_tcp().
    """

    reader: asyncio.StreamReader
    writer: Any  # asyncio.StreamWriter, or anything with write/drain/close/wait_closed
    info: DeviceInfo | None = None
    props: dict[str, Prop] = field(default_factory=dict)
    values: dict[str, object] = field(default_factory=dict)
    secure: bool = False

    def __post_init__(self) -> None:
        self._by_id: dict[int, Prop] = {}
        self._frames = FrameParser()
        self._seq = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._kind: dict[int, tuple[int, int | None]] = {}
        self._listeners: list[Callable[[dict[str, object]], None]] = []
        self._reader_task: asyncio.Task | None = None
        self._handshake: asyncio.Future | None = None
        self._tx: CipherState | None = None
        self._rx: CipherState | None = None
        self.peer_key: bytes | None = None  # the device's static key (secure sessions)
        self.closed = asyncio.Event()
        self.error: SmartError | None = None  # why the connection ended

    # ----- setup -----

    @classmethod
    async def connect_tcp(
        cls,
        host: str,
        port: int,
        identity: HostIdentity,
        *,
        pairing: bool = False,
        local_addr: tuple[str, int] | None = None,
    ) -> SmartDevice:
        """Open a secure session. Only devices `identity` has paired with are
        accepted, unless `pairing` (the device's pairing window is open): then
        the device's key is remembered."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, local_addr=local_addr), CONNECT_TIMEOUT
        )
        return await cls.connect_secure(reader, writer, identity, pairing=pairing)

    @classmethod
    async def connect_ble(cls, name_or_address: str, identity: HostIdentity, *, pairing: bool = False) -> SmartDevice:
        """A secure session over BLE (the device's pairing window must be open)."""
        reader, writer = await open_ble(name_or_address)
        return await cls.connect_secure(reader, writer, identity, pairing=pairing)

    @classmethod
    async def connect_secure(cls, reader, writer, identity: HostIdentity, *, pairing: bool = False) -> SmartDevice:
        """Noise handshake on an untrusted transport, then HELLO and DESCRIBE."""
        dev = cls(reader, writer, secure=True)
        try:
            dev._reader_task = asyncio.create_task(dev._read_loop())
            await dev._run_handshake(identity, pairing)
            await dev._start(REQUEST_TIMEOUT)
            if dev.info.public_key is not None and dev.info.public_key != dev.peer_key:
                raise SmartError("the device's INFO doesn't match its handshake key")
            if pairing:
                identity.remember(dev.info.device_id, dev.peer_key)
        except BaseException:
            await dev.close()
            raise
        return dev

    @classmethod
    async def connect_plain(cls, reader, writer, hello_timeout: float = REQUEST_TIMEOUT) -> SmartDevice:
        """A trusted transport: plain packets, no handshake."""
        dev = cls(reader, writer)
        try:
            dev._reader_task = asyncio.create_task(dev._read_loop())
            await dev._start(hello_timeout)
        except BaseException:
            await dev.close()
            raise
        return dev

    @classmethod
    async def connect_serial(cls, path: str, *, baudrate: int = BAUDRATE) -> SmartDevice:
        reader, writer = await open_serial(path, baudrate)
        return await cls.connect_plain(reader, writer, SERIAL_HELLO_TIMEOUT)

    async def _run_handshake(self, identity: HostIdentity, pairing: bool) -> None:
        loop = asyncio.get_running_loop()
        hs = NoiseXXInitiator(identity.secret)
        self._handshake = loop.create_future()
        await self._send_body(bytes([K_HS1]) + hs.write1())
        msg2 = await asyncio.wait_for(self._handshake, REQUEST_TIMEOUT)
        if msg2[0] != K_HS2:
            raise SmartError("handshake failed: unexpected reply")
        hs.read2(msg2[1:])
        self.peer_key = hs.rs
        if not pairing and not identity.knows(hs.rs):
            # don't even finish the handshake with an impostor
            raise SmartError(
                f"unknown device key {fingerprint(hs.rs)}: pair with it first (smartctl ... pair)"
            )
        msg3, self._tx, self._rx = hs.write3()
        self._handshake = None
        await self._send_body(bytes([K_HS3]) + msg3)
        # The device decides after message 3: a REJECT now fails the HELLO below.

    async def _start(self, hello_timeout: float) -> None:
        """HELLO (repeated until `hello_timeout`), DESCRIBE every property, GET all values."""
        self.info = parse_info(await self._hello(hello_timeout))
        for pid in range(self.info.prop_count):
            prop = parse_prop(await self._request(DESCRIBE, bytes([pid])))
            self._by_id[prop.id] = prop
            self.props[prop.name] = prop
        await self.refresh()

    async def refresh(self) -> dict[str, object]:
        """Re-read every visible value."""
        await self._request(GET, bytes([ALL]))
        return self.values

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()
        self.closed.set()

    def add_listener(self, callback: Callable[[dict[str, object]], None]) -> Callable[[], None]:
        """`callback(changed)` on every EVENT; returns a remover."""
        self._listeners.append(callback)
        return lambda: self._listeners.remove(callback)

    # ----- requests -----

    async def ping(self) -> None:
        await self._request(PING)

    async def get(self, name: str):
        prop = self.prop(name)
        await self._request(GET, bytes([prop.id]))
        return self.values.get(name)

    async def set(self, changes: dict[str, object]) -> None:
        """Set several properties at once (all-or-nothing on the device)."""
        payload = bytearray()
        for name, value in changes.items():
            prop = self.prop(name)
            payload.append(prop.id)
            payload += prop.encode(value)
        await self._request(SET, bytes(payload))

    async def trigger(self, name: str) -> None:
        """Run an action property."""
        await self.set({name: None})

    async def pair(self, identity: HostIdentity) -> None:
        """Over a trusted session (USB): make the device trust `identity`."""
        if self.secure:
            raise SmartError("pairing a new host needs a trusted connection (USB)")
        await self._request(PAIR, identity.public)
        if self.info.public_key is None:
            raise SmartError("the device has no key (no secure sessions)")
        identity.remember(self.info.device_id, self.info.public_key)

    async def unpair(self, host_key: bytes | None = None) -> None:
        """Remove a host from the device: `host_key`, or every host (trusted session only).

        Over a secure session only this host itself can be removed; the device
        then hangs up."""
        payload = host_key or b""
        if self.secure and not host_key:
            raise SmartError("over the network a host can only unpair itself")
        await self._request(UNPAIR, payload)

    async def update(self, image: bytes, progress: Callable[[int, int], None] | None = None) -> None:
        """Send a signed image (firmware + manifest, see smartsign.py). The
        device checks the signature, model and hash, installs it and reboots:
        the connection drops right after."""
        if not self.info.ota:
            raise SmartError("this device doesn't take firmware updates")
        if len(image) <= MANIFEST_LEN or image[-MANIFEST_LEN:][:8] != b"SMARTFW1":
            raise SmartError("not a signed image: sign it with smartsign.py first")
        firmware, manifest = image[:-MANIFEST_LEN], image[-MANIFEST_LEN:]
        if struct.unpack_from("<I", manifest, 16)[0] != len(firmware):
            raise SmartError("the image doesn't match its manifest")
        await self._request(OTA_BEGIN, manifest, timeout=15)  # the device may erase flash here
        chunk = max(16, min(self.info.max_payload, 240) - 4)
        # Up to OTA_WINDOW chunks in flight: the link keeps them in order, and
        # the device refuses any chunk that doesn't follow the previous one.
        in_flight: list[asyncio.Task] = []
        try:
            for off in range(0, len(firmware), chunk):
                payload = struct.pack("<I", off) + firmware[off : off + chunk]
                in_flight.append(asyncio.ensure_future(self._request(OTA_DATA, payload, timeout=10)))
                await asyncio.sleep(0)  # let it write now, in order
                if len(in_flight) >= OTA_WINDOW:
                    await in_flight.pop(0)
                if progress:
                    progress(max(0, off + chunk - len(in_flight) * chunk), len(firmware))
            for task in in_flight:
                await task
        finally:
            for task in in_flight:
                task.cancel()
        if progress:
            progress(len(firmware), len(firmware))
        await self._request(OTA_END, timeout=30)

    def prop(self, name: str) -> Prop:
        """The property called `name`; SmartError if there's none."""
        if name not in self.props:
            raise SmartError(f"no property {name!r}")
        return self.props[name]

    async def _hello(self, timeout: float) -> bytes:
        """HELLO until the device answers: it may still be booting."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            try:
                # a late INFO to an earlier attempt is ignored: its seq is no longer pending
                return await self._request(
                    HELLO, bytes([PROTO_VERSION]), timeout=max(0.05, min(HELLO_RETRY, deadline - loop.time()))
                )
            except asyncio.TimeoutError:
                if loop.time() >= deadline:
                    raise SmartError("no answer to HELLO: not a smart-core device, or it doesn't boot") from None

    async def _send_body(self, body: bytes) -> None:
        self.writer.write(frame(body))
        await self.writer.drain()

    async def _request(self, msg_type: int, payload: bytes = b"", *, timeout: float = REQUEST_TIMEOUT) -> bytes:
        if self.closed.is_set():
            raise self.error or SmartError("connection closed")
        self._seq = self._seq % 255 + 1  # 1..255; 0 is reserved for events
        seq = self._seq
        fut = asyncio.get_running_loop().create_future()
        self._pending[seq] = fut
        self._kind[seq] = (msg_type, payload[0] if payload else None)
        try:
            raw = bytes([msg_type, seq]) + payload
            if self.secure:
                await self._send_body(bytes([K_DATA]) + self._tx.encrypt(raw))
            else:
                self.writer.write(build_packet(msg_type, seq, payload))
                await self.writer.drain()
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(seq, None)
            self._kind.pop(seq, None)

    # ----- incoming -----

    def _fail(self, err: SmartError) -> None:
        self.error = err
        for fut in [*self._pending.values(), self._handshake]:
            if fut is not None and not fut.done():
                fut.set_exception(err)
        self.closed.set()

    async def _read_loop(self) -> None:
        try:
            while True:
                data = await self.reader.read(1024)
                if not data:
                    raise SmartError("connection closed")
                for body in self._frames.feed(data):
                    self._on_frame(body)
        except Exception as err:  # noqa: BLE001 - fail every waiter with the reason
            self._fail(err if isinstance(err, SmartError) else SmartError(str(err)))

    def _on_frame(self, body: bytes) -> None:
        if not self.secure:
            packet = parse_plain(body)
            if packet:
                self._handle(*packet)
            return
        kind = body[0]
        if kind == K_REJECT:
            code = body[1] if len(body) > 1 else 0
            raise RejectedError(REJECTS.get(code, f"rejected ({code})"), code)
        if self._handshake is not None and not self._handshake.done():
            self._handshake.set_result(body)
            return
        if kind == K_DATA and self._rx is not None:
            raw = self._rx.decrypt(body[1:])  # raises on tampering: the session ends
            if len(raw) >= 2:
                self._handle(raw[0], raw[1], raw[2:])

    def _apply_values(self, payload: bytes) -> dict[str, object]:
        changed: dict[str, object] = {}
        pos = 0
        while pos < len(payload):
            prop = self._by_id.get(payload[pos])
            if prop is None:  # can't know its size: drop the rest
                break
            value, pos = prop.decode(payload, pos + 1)
            self.values[prop.name] = value
            changed[prop.name] = value
        return changed

    def _handle(self, msg_type: int, seq: int, payload: bytes) -> None:
        if msg_type == EVENT:
            changed = self._apply_values(payload)
            for cb in list(self._listeners):
                cb(changed)
            return
        fut = self._pending.get(seq)
        if msg_type == VALUES:
            self._apply_values(payload)
            # a single GET ends with its VALUES; GET FF ends with ACK
            if fut and not fut.done() and self._kind.get(seq) != (GET, ALL):
                fut.set_result(payload)
            return
        if fut is None or fut.done():
            return
        if msg_type == ERROR:
            code = payload[0] if payload else 0
            pid = payload[1] if len(payload) > 1 else ALL
            prop = self._by_id.get(pid)
            name = prop.name if prop else None
            msg = ERRORS.get(code, f"error {code}") + (f" ({name})" if name else "")
            fut.set_exception(SmartError(msg, code, name))
        else:
            fut.set_result(payload)


# ---------- targets ----------

def parse_target(target: str) -> tuple[str, str, int]:
    """("serial", path, 0), ("tcp", host, port) or ("ble", name or address, 0)."""
    kind, _, address = target.partition(":")
    if kind in ("serial", "ble") and address:
        return kind, address, 0
    if kind == "tcp" and address:
        host, port = address, DEFAULT_TCP_PORT
        if address.startswith("["):  # [IPv6]:port
            host, _, rest = address[1:].partition("]")
            if rest.startswith(":"):
                port = int(rest[1:])
        elif address.count(":") == 1:
            host, port_str = address.split(":")
            port = int(port_str)
        return kind, host, port
    raise SmartError(f"bad target {target!r}: use serial:PORT, tcp:HOST[:PORT] or ble:NAME")


async def connect(target: str, identity: HostIdentity | None = None, *, pairing: bool = False) -> SmartDevice:
    """Connect to "serial:COM5", "serial:/dev/ttyACM0", "tcp:host[:port]" or "ble:LumenC3-62B2".

    TCP and BLE need `identity` (secure session); with `pairing` the device's
    pairing window must be open, and the device is remembered."""
    kind, address, port = parse_target(target)
    if kind == "serial":
        return await SmartDevice.connect_serial(address)
    if identity is None:
        raise SmartError("a network connection needs a host identity (key)")
    if kind == "ble":
        return await SmartDevice.connect_ble(address, identity, pairing=pairing)
    return await SmartDevice.connect_tcp(address, port, identity, pairing=pairing)
