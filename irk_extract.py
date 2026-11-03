#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "cryptography>=42",
#     "rich>=13.7",
# ]
# ///
"""Get a Bluetooth LE device's IRK out of an iPhone bond over USB, no jailbreak needed.

With Apple's Bluetooth logging profile installed, the iPhone streams its HCI traffic over
USB (com.apple.bluetooth.BTPacketLogger, via pymobiledevice3). The link is encrypted over
the air, but HCI sits below that, so when a device re-pairs, the SMP key distribution shows
both sides' Identity Resolving Keys in the clear.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import threading
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

__version__ = "0.1.0"

PROFILE_ID = "com.apple.bluetooth.logging"
PROFILE_PAGE = "https://developer.apple.com/bug-reporting/profiles-and-logs/?name=bluetooth"
PMD3_REQUIREMENT = "pymobiledevice3>=11.49"
USBMUXD_SOCKETS = ("/var/run/usbmuxd", "/run/usbmuxd")

PKLG_COMMAND, PKLG_EVENT, PKLG_ACL_SENT, PKLG_ACL_RECV = 0x00, 0x01, 0x02, 0x03
PKLG_NOTE = 0xFC
PKLG_HEADER = 13
PKLG_MAX_RECORD = 0x20000

L2CAP_ATT, L2CAP_SMP, L2CAP_SMP_BREDR = 0x0004, 0x0006, 0x0007
UUID_DEVICE_NAME, UUID_CHARACTERISTIC = 0x2A00, 0x2803
ATT_REQUESTS = {0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x16, 0x18, 0x20}
ATT_RESPONSES = {0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x17, 0x19, 0x21}

SMP_NAMES = {
    0x01: "Pairing Request",
    0x02: "Pairing Response",
    0x03: "Pairing Confirm",
    0x04: "Pairing Random",
    0x05: "Pairing Failed",
    0x06: "Encryption Information (LTK)",
    0x07: "Central Identification",
    0x08: "Identity Information (IRK)",
    0x09: "Identity Address Information",
    0x0A: "Signing Information (CSRK)",
    0x0B: "Security Request",
    0x0C: "Pairing Public Key",
    0x0D: "Pairing DHKey Check",
}
SMP_FAILURES = {
    0x01: ("Passkey Entry Failed", "The passkey was cancelled or typed wrong. Try again."),
    0x02: ("OOB Not Available", ""),
    0x03: (
        "Authentication Requirements",
        "The device and the iPhone couldn't agree on a security level.",
    ),
    0x04: ("Confirm Value Failed", "Usually a mistyped passkey. Try again."),
    0x05: (
        "Pairing Not Supported",
        "The device refused to pair. Put it in pairing mode, or reset it if another phone owns it.",
    ),
    0x06: ("Encryption Key Size", ""),
    0x07: ("Command Not Supported", ""),
    0x08: (
        "Unspecified Reason",
        "Often the device still holds the old bond. Reset its pairing, then pair again.",
    ),
    0x09: ("Repeated Attempts", "Too many tries in a row. Wait a minute, then pair again."),
    0x0A: ("Invalid Parameters", ""),
    0x0B: ("DHKey Check Failed", "Try pairing again."),
    0x0C: ("Numeric Comparison Failed", "The codes didn't match, or one side said no."),
    0x0D: ("BR/EDR pairing in progress", "Wait for the Classic pairing to finish."),
    0x0E: ("Cross-transport Key Derivation not allowed", ""),
    0x0F: ("Key Rejected", ""),
    0x10: ("Busy", "Try again in a moment."),
}
HCI_REASONS = {
    0x05: "authentication failure",
    0x06: "key missing",
    0x08: "connection timeout",
    0x13: "the device closed it",
    0x16: "the iPhone closed it",
    0x3B: "unacceptable parameters",
    0x3D: "MIC failure",
    0x3E: "never got established",
}
PEER_ADDRESS_TYPES = {0: "public", 1: "random", 2: "public identity", 3: "random identity"}
IO_CAPABILITIES = {
    0: "DisplayOnly",
    1: "DisplayYesNo",
    2: "KeyboardOnly",
    3: "NoInputNoOutput",
    4: "KeyboardDisplay",
}
KEY_ENC, KEY_ID, KEY_SIGN, KEY_LINK = 0x01, 0x02, 0x04, 0x08


class SetupError(Exception):
    pass


class TraceError(Exception):
    pass


# --- Bluetooth helpers ----------------------------------------------------------------------


def fmt_addr(le: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(le))


def addr_bytes_le(addr: str) -> bytes:
    return bytes(reversed(bytes.fromhex(addr.replace(":", ""))))


def random_kind(addr: str) -> str:
    top = int(addr[:2], 16) >> 6
    return {0b00: "non-resolvable private", 0b01: "resolvable private", 0b11: "random static"}.get(top, "random")


def is_rpa(addr: str | None) -> bool:
    return bool(addr) and int(addr[:2], 16) >> 6 == 0b01


def ah(irk: bytes, prand: bytes) -> bytes:
    """Random address hash, Bluetooth Core Vol 3 Part H 2.2.2. ``irk`` is MSB first."""
    encryptor = Cipher(algorithms.AES(irk), modes.ECB()).encryptor()
    return (encryptor.update(bytes(13) + prand) + encryptor.finalize())[13:]


def resolves(irk: bytes, addr: str) -> bool:
    raw = bytes.fromhex(addr.replace(":", ""))
    return is_rpa(addr) and ah(irk, raw[:3]) == raw[3:]


def key_dist(bits: int) -> str:
    names = [
        name
        for bit, name in ((KEY_ENC, "EncKey"), (KEY_ID, "IdKey"), (KEY_SIGN, "SignKey"), (KEY_LINK, "LinkKey"))
        if bits & bit
    ]
    return "+".join(names) or "nothing"


def _io_method(initiator: int, responder: int, secure: bool) -> str:
    if 3 in (initiator, responder):
        return "Just Works"
    if 2 in (initiator, responder):
        return "Passkey Entry"
    if 0 in (initiator, responder):
        return "Passkey Entry" if 4 in (initiator, responder) else "Just Works"
    if secure:
        return "Numeric Comparison"
    return "Just Works" if (initiator, responder) == (1, 1) else "Passkey Entry"


def pairing_method(request: bytes, response: bytes) -> str:
    secure = bool(request[3] & 0x08 and response[3] & 0x08)
    family = "LE Secure Connections" if secure else "LE Legacy Pairing"
    if (secure and (request[2] or response[2])) or (request[2] and response[2]):
        return f"{family}, Out of Band"
    if not (request[3] & 0x04 or response[3] & 0x04):
        return f"{family}, Just Works"
    return f"{family}, {_io_method(request[1], response[1], secure)}"


def decode_name(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def ad_local_name(data: bytes) -> str | None:
    pos = 0
    while pos + 1 < len(data):
        length = data[pos]
        if length == 0:
            break
        if data[pos + 1] in (0x08, 0x09):
            return decode_name(data[pos + 2 : pos + 1 + length]) or None
        pos += 1 + length
    return None


def name_near(blob: bytes, target: str) -> str:
    """The full advertised name around ``target`` in an opaque blob, if it sits in an AD structure."""
    needle = target.lower().encode()
    i = blob.lower().find(needle)
    for start in range(i, max(i - 248, 1), -1):
        length, ad_type = blob[start - 2], blob[start - 1]
        if ad_type in (0x08, 0x09) and length >= 2 and start - 1 + length >= i + len(needle):
            name = decode_name(blob[start : start - 1 + length])
            if target.casefold() in name.casefold():
                return name
    return target


def clock(ts: float) -> str:
    # The iPhone stamps records with its local wall clock as if it were UTC.
    return time.strftime("%H:%M:%S", time.gmtime(ts))


# --- PacketLogger traces --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Record:
    ts: float
    kind: int
    payload: bytes


class PklgReader:
    """Incremental PacketLogger parser: feed bytes as they arrive, get whole records back."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._order: str | None = None
        self.offset = 0

    def feed(self, data: bytes) -> list[Record]:
        self._buf += data
        if self._order is None:
            if len(self._buf) < 4:
                return []
            big = int.from_bytes(self._buf[:4], "big")
            self._order = ">" if 9 <= big <= PKLG_MAX_RECORD else "<"
        records = []
        pos = 0
        while pos + PKLG_HEADER <= len(self._buf):
            length, secs, usecs = struct.unpack_from(self._order + "III", self._buf, pos)
            if not 9 <= length <= PKLG_MAX_RECORD:
                raise TraceError(f"not a PacketLogger trace, or corrupt at byte {self.offset + pos}")
            end = pos + 4 + length
            if end > len(self._buf):
                break
            records.append(Record(secs + usecs / 1e6, self._buf[pos + 12], bytes(self._buf[pos + 13 : end])))
            pos = end
        del self._buf[:pos]
        self.offset += pos
        return records


def read_traces(path: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (name, bytes) for a .pklg file, or for every .pklg inside a sysdiagnose tarball."""
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tar:
            for member in tar:
                if member.isfile() and member.name.endswith(".pklg"):
                    yield member.name, tar.extractfile(member).read()
        return
    yield str(path), path.read_bytes()


# --- HCI tracking ---------------------------------------------------------------------------


class Ev(Enum):
    PHONE = auto()
    CONNECTED = auto()
    CONNECT_FAILED = auto()
    DISCONNECTED = auto()
    NAMED = auto()
    SECURITY_REQUEST = auto()
    PAIRING_REQUEST = auto()
    PAIRING_RESPONSE = auto()
    PUBLIC_KEY = auto()
    PAIRING_FAILED = auto()
    ENCRYPTED = auto()
    ENCRYPTION_FAILED = auto()
    IRK = auto()
    IDENTITY = auto()
    OTHER_KEY = auto()


@dataclass(eq=False)
class Conn:
    handle: int
    peer: str | None
    peer_type: int | None
    started: float
    peer_rpa: str | None = None
    name: str | None = None
    name_source: str | None = None
    ended: float | None = None
    request: bytes | None = None
    request_from_phone: bool = True
    response: bytes | None = None
    failed: int | None = None
    encrypted: bool = False
    smp: bool = False
    public_keys: int = 0
    peer_irk: bytes | None = None
    peer_identity: str | None = None
    phone_irk: bytes | None = None
    phone_identity: str | None = None
    name_handle: int | None = None
    att_pending: str | None = None

    @property
    def label(self) -> str:
        return self.name or self.peer or f"handle 0x{self.handle:03X}"

    def addresses(self) -> list[str]:
        return [a for a in (self.peer, self.peer_rpa) if a]

    def peer_keys(self) -> int | None:
        if not self.response or len(self.response) < 7:
            return None
        return self.response[6] if self.request_from_phone else self.response[5]

    def describe_peer(self) -> str:
        if self.peer is None:
            return "unknown address"
        if self.peer_type is None:
            return f"{self.peer} (Classic)"
        if self.peer_type in (2, 3):
            via = f", resolved from {self.peer_rpa}" if self.peer_rpa else ""
            return f"{self.peer} ({PEER_ADDRESS_TYPES[self.peer_type]}{via})"
        if self.peer_type == 1:
            return f"{self.peer} ({random_kind(self.peer)})"
        return f"{self.peer} (public)"


@dataclass(frozen=True, slots=True)
class Event:
    kind: Ev
    ts: float
    conn: Conn | None = None
    from_phone: bool = False
    code: int = 0
    addr: str | None = None


class Tracker:
    """Follows LE/Classic connections, GATT names and SMP pairing in a stream of records."""

    def __init__(self, target: str | None = None) -> None:
        self.target = (target or "").strip() or None
        self.conns: list[Conn] = []
        self.open: dict[int, Conn] = {}
        self.notes: dict[str, str] = {}
        self.adv_names: dict[str, str] = {}
        self.name_blobs: deque[bytes] = deque(maxlen=512)
        self.fragments: dict[tuple[int, bool], bytearray] = {}
        self.cancelled_connects = 0
        self.records = 0
        self.hci_records = 0

    def is_target(self, conn: Conn | None) -> bool:
        return bool(conn and self.target and conn.name and self.target.casefold() in conn.name.casefold())

    def paired_peers(self) -> list[Conn]:
        latest: dict[bytes, Conn] = {}
        for conn in self.conns:
            if conn.peer_irk:
                latest.pop(conn.peer_irk, None)
                latest[conn.peer_irk] = conn
        return list(latest.values())

    def feed(self, rec: Record) -> list[Event]:
        self.records += 1
        out: list[Event] = []
        if rec.kind in (PKLG_COMMAND, PKLG_EVENT, PKLG_ACL_SENT, PKLG_ACL_RECV):
            self.hci_records += 1
        if rec.kind == PKLG_EVENT and rec.payload:
            self._event(rec.ts, rec.payload, out)
        elif rec.kind in (PKLG_ACL_SENT, PKLG_ACL_RECV):
            self._acl(rec.ts, rec.payload, rec.kind == PKLG_ACL_SENT, out)
        elif rec.kind == PKLG_NOTE:
            self._note(rec.ts, rec.payload, out)
        if self.target and (rec.kind == PKLG_EVENT or rec.kind >= PKLG_NOTE):
            self._scan_blob(rec.ts, rec.payload, out)
        return out

    def _note(self, ts: float, payload: bytes, out: list[Event]) -> None:
        key, sep, value = payload.decode("utf-8", "replace").partition(": ")
        if sep and key in ("Product", "Software", "Chipset", "Address"):
            self.notes[key] = value.strip()
            if key == "Software":
                out.append(Event(Ev.PHONE, ts))

    def _event(self, ts: float, p: bytes, out: list[Event]) -> None:
        code = p[0]
        if code == 0x3E and len(p) >= 3:
            self._le_meta(ts, p[2], p[3:], out)
        elif code == 0x03 and len(p) >= 12 and p[2] == 0 and p[11] == 0x01:
            handle = struct.unpack_from("<H", p, 3)[0] & 0x0FFF
            self._connected(ts, handle, fmt_addr(p[5:11]), None, None, out)
        elif code == 0x05 and len(p) >= 6 and p[2] == 0:
            handle = struct.unpack_from("<H", p, 3)[0] & 0x0FFF
            conn = self.open.pop(handle, None)
            self.fragments.pop((handle, True), None)
            self.fragments.pop((handle, False), None)
            if conn:
                conn.ended = ts
                out.append(Event(Ev.DISCONNECTED, ts, conn, code=p[5]))
        elif code in (0x08, 0x59) and len(p) >= 6:
            conn = self.open.get(struct.unpack_from("<H", p, 3)[0] & 0x0FFF)
            if conn and p[2] == 0 and p[5]:
                conn.encrypted = True
                out.append(Event(Ev.ENCRYPTED, ts, conn))
            elif conn and p[2]:
                out.append(Event(Ev.ENCRYPTION_FAILED, ts, conn, code=p[2]))
        elif code == 0x30 and len(p) >= 5 and p[2] == 0:
            conn = self.open.get(struct.unpack_from("<H", p, 3)[0] & 0x0FFF)
            if conn and not conn.encrypted:
                conn.encrypted = True
                out.append(Event(Ev.ENCRYPTED, ts, conn))
        elif code == 0x07 and len(p) >= 10 and p[2] == 0:
            name = decode_name(p[9:])
            if name:
                self._advertised(ts, fmt_addr(p[3:9]), name, "Classic remote name", out)

    def _le_meta(self, ts: float, sub: int, ev: bytes, out: list[Event]) -> None:
        if sub in (0x01, 0x0A, 0x29) and len(ev) >= 11:
            handle = struct.unpack_from("<H", ev, 1)[0] & 0x0FFF
            peer = fmt_addr(ev[5:11])
            if ev[0] != 0:
                if ev[0] == 0x02 and peer == "00:00:00:00:00:00":
                    self.cancelled_connects += 1
                else:
                    out.append(Event(Ev.CONNECT_FAILED, ts, code=ev[0], addr=peer))
                return
            peer_rpa = None
            if sub != 0x01 and len(ev) >= 23 and any(ev[17:23]):
                peer_rpa = fmt_addr(ev[17:23])
            self._connected(ts, handle, peer, ev[4], peer_rpa, out)
        elif sub == 0x02 and len(ev) >= 10 and ev[0] == 1:
            data = ev[10 : 10 + ev[9]]
            name = ad_local_name(data)
            if name:
                self._advertised(ts, fmt_addr(ev[3:9]), name, "advertising data", out)
        elif sub == 0x0D and ev:
            pos = 1
            for _ in range(ev[0]):
                if pos + 24 > len(ev):
                    break
                length = ev[pos + 23]
                name = ad_local_name(ev[pos + 24 : pos + 24 + length])
                if name:
                    self._advertised(ts, fmt_addr(ev[pos + 3 : pos + 9]), name, "advertising data", out)
                pos += 24 + length

    def _connected(
        self,
        ts: float,
        handle: int,
        peer: str | None,
        peer_type: int | None,
        peer_rpa: str | None,
        out: list[Event],
    ) -> Conn:
        conn = Conn(handle, peer, peer_type, ts, peer_rpa=peer_rpa)
        self.conns.append(conn)
        self.open[handle] = conn
        self.fragments.pop((handle, True), None)
        self.fragments.pop((handle, False), None)
        for addr in conn.addresses():
            if addr in self.adv_names:
                conn.name, conn.name_source = self.adv_names[addr], "advertising data"
                break
        else:
            if self.target:
                for blob in self.name_blobs:
                    if self._blob_has(conn, blob):
                        conn.name, conn.name_source = name_near(blob, self.target), "Apple scan report"
                        break
        if peer is not None:
            out.append(Event(Ev.CONNECTED, ts, conn))
        return conn

    def _advertised(self, ts: float, addr: str, name: str, source: str, out: list[Event]) -> None:
        self.adv_names.pop(addr, None)
        self.adv_names[addr] = name
        if len(self.adv_names) > 4096:
            del self.adv_names[next(iter(self.adv_names))]
        for conn in self.open.values():
            if conn.name is None and addr in conn.addresses():
                self._set_name(ts, conn, name, source, out)

    def _blob_has(self, conn: Conn, blob: bytes) -> bool:
        return any(addr_bytes_le(addr) in blob for addr in conn.addresses())

    def _scan_blob(self, ts: float, payload: bytes, out: list[Event]) -> None:
        if self.target.lower().encode() not in payload.lower():
            return
        self.name_blobs.append(payload)
        for conn in self.open.values():
            if conn.name is None and self._blob_has(conn, payload):
                self._set_name(ts, conn, name_near(payload, self.target), "Apple scan report", out)

    def _set_name(self, ts: float, conn: Conn, name: str, source: str, out: list[Event]) -> None:
        if not name:
            return
        changed = conn.name != name
        conn.name, conn.name_source = name, source
        if changed:
            out.append(Event(Ev.NAMED, ts, conn))

    def _acl(self, ts: float, p: bytes, sent: bool, out: list[Event]) -> None:
        if len(p) < 4:
            return
        flags, length = struct.unpack_from("<HH", p)
        handle, boundary = flags & 0x0FFF, (flags >> 12) & 0x3
        data = p[4 : 4 + length]
        key = (handle, sent)
        if boundary == 0b01:
            buf = self.fragments.get(key)
            if buf is None:
                return
            buf += data
        else:
            buf = self.fragments[key] = bytearray(data)
        if len(buf) < 4:
            return
        l2len, cid = struct.unpack_from("<HH", buf)
        if len(buf) - 4 < l2len:
            return
        del self.fragments[key]
        pdu = bytes(buf[4 : 4 + l2len])
        if not pdu or cid not in (L2CAP_ATT, L2CAP_SMP, L2CAP_SMP_BREDR):
            return
        conn = self.open.get(handle)
        if conn is None:
            conn = self._connected(ts, handle, None, None, None, out)
        if cid == L2CAP_ATT:
            self._att(ts, conn, sent, pdu, out)
        else:
            self._smp(ts, conn, sent, pdu, out)

    def _att(self, ts: float, conn: Conn, sent: bool, pdu: bytes, out: list[Event]) -> None:
        op = pdu[0]
        if sent:
            if op == 0x08 and len(pdu) == 7:
                uuid = struct.unpack_from("<H", pdu, 5)[0]
                conn.att_pending = {UUID_DEVICE_NAME: "name", UUID_CHARACTERISTIC: "chars"}.get(uuid)
            elif op == 0x0A and len(pdu) >= 3:
                handle = struct.unpack_from("<H", pdu, 1)[0]
                conn.att_pending = "read-name" if handle == conn.name_handle else None
            elif op in ATT_REQUESTS:
                conn.att_pending = None
            return
        if op not in ATT_RESPONSES:
            return
        pending, conn.att_pending = conn.att_pending, None
        if op == 0x09 and len(pdu) >= 2 and pdu[1] >= 2 and pending in ("name", "chars"):
            size, entries = pdu[1], pdu[2:]
            for off in range(0, len(entries) - size + 1, size):
                entry = entries[off : off + size]
                if pending == "name":
                    conn.name_handle = struct.unpack_from("<H", entry)[0]
                    self._set_name(ts, conn, decode_name(entry[2:]), "GATT Device Name", out)
                    break
                if size == 7 and struct.unpack_from("<H", entry, 5)[0] == UUID_DEVICE_NAME:
                    conn.name_handle = struct.unpack_from("<H", entry, 3)[0]
        elif op == 0x0B and pending == "read-name":
            self._set_name(ts, conn, decode_name(pdu[1:]), "GATT Device Name", out)

    def _smp(self, ts: float, conn: Conn, sent: bool, pdu: bytes, out: list[Event]) -> None:
        op = pdu[0]
        conn.smp = True
        if op == 0x01 and len(pdu) >= 7:
            conn.request, conn.request_from_phone = pdu, sent
            conn.response, conn.failed, conn.public_keys = None, None, 0
            out.append(Event(Ev.PAIRING_REQUEST, ts, conn, from_phone=sent))
        elif op == 0x02 and len(pdu) >= 7:
            conn.response = pdu
            out.append(Event(Ev.PAIRING_RESPONSE, ts, conn, from_phone=sent))
        elif op == 0x0B:
            out.append(Event(Ev.SECURITY_REQUEST, ts, conn, from_phone=sent))
        elif op == 0x0C:
            conn.public_keys += 1
            if conn.public_keys == 1:
                out.append(Event(Ev.PUBLIC_KEY, ts, conn, from_phone=sent))
        elif op == 0x05 and len(pdu) >= 2:
            conn.failed = pdu[1]
            out.append(Event(Ev.PAIRING_FAILED, ts, conn, from_phone=sent, code=pdu[1]))
        elif op == 0x08 and len(pdu) >= 17:
            irk = bytes(reversed(pdu[1:17]))
            if sent:
                conn.phone_irk = irk
            else:
                conn.peer_irk = irk
            out.append(Event(Ev.IRK, ts, conn, from_phone=sent))
        elif op == 0x09 and len(pdu) >= 8:
            identity = f"{fmt_addr(pdu[2:8])} ({'public' if pdu[1] == 0 else 'random static'})"
            if sent:
                conn.phone_identity = identity
            else:
                conn.peer_identity = identity
            out.append(Event(Ev.IDENTITY, ts, conn, from_phone=sent))
        elif op in (0x06, 0x07, 0x0A):
            out.append(Event(Ev.OTHER_KEY, ts, conn, from_phone=sent, code=op))


class Session:
    """Decides when a capture has what it came for."""

    GRACE_FOUND = 2.0
    GRACE_UNMATCHED = 20.0
    GRACE_NO_IRK = 3.0

    def __init__(self, tracker: Tracker) -> None:
        self.tracker = tracker
        self.stop_at: float | None = None
        self.no_irk: Conn | None = None

    def _stop(self, at: float) -> None:
        self.stop_at = at if self.stop_at is None else min(self.stop_at, at)

    def update(self, events: list[Event], now: float) -> None:
        for ev in events:
            conn = ev.conn
            if ev.kind is Ev.IRK and not ev.from_phone:
                if self.tracker.is_target(conn):
                    self._stop(now + self.GRACE_FOUND)
                else:
                    self._stop(now + self.GRACE_UNMATCHED)
            elif ev.kind is Ev.NAMED and conn.peer_irk and self.tracker.is_target(conn):
                self._stop(now + self.GRACE_FOUND)
            elif (
                ev.kind is Ev.ENCRYPTED
                and conn.smp
                and not conn.peer_irk
                and self.tracker.is_target(conn)
                and conn.peer_keys() is not None
                and not conn.peer_keys() & KEY_ID
            ):
                self.no_irk = conn
                self._stop(now + self.GRACE_NO_IRK)

    def done(self, now: float) -> bool:
        return self.stop_at is not None and now >= self.stop_at


# --- Narration ------------------------------------------------------------------------------


@dataclass(slots=True)
class Line:
    icon: str
    text: Text

    def append(self, text: str, style: str = "") -> None:
        self.text.append(text, style)


class Narrator:
    def __init__(self, console: Console, tracker: Tracker) -> None:
        self.console = console
        self.tracker = tracker
        self.bond_hint_shown = False

    def show(self, ev: Event) -> None:
        line = self.describe(ev)
        if line is not None:
            grid = Table.grid(padding=(0, 1))
            grid.add_column(no_wrap=True, width=8, style="dim")
            grid.add_column(no_wrap=True, width=2)
            grid.add_column(overflow="fold")
            grid.add_row("" if ev.kind is Ev.PHONE else clock(ev.ts), line.icon, line.text)
            self.console.print(grid)
        if ev.kind is Ev.PAIRING_RESPONSE:
            self._warn_no_idkey(ev.conn)

    def _line(self, icon: str, *parts: str | tuple[str, str], style: str = "") -> Line:
        return Line(icon, Text.assemble(*parts, style=style))

    def _who(self, conn: Conn, from_phone: bool) -> str:
        return "iPhone" if from_phone else conn.label

    def describe(self, ev: Event) -> Line | None:
        conn = ev.conn
        target = self.tracker.is_target(conn)
        interesting = target or (conn is not None and conn.smp)
        if ev.kind is Ev.PHONE:
            notes = self.tracker.notes
            software = notes.get("Software", "").replace("Version ", "iOS ").split(" (")[0]
            bits = [notes.get("Product"), software, notes.get("Chipset", "").split(",")[0]]
            return self._line("📱", "Capturing from ", (", ".join(b for b in bits if b), "bold"))
        if ev.kind is Ev.CONNECTED:
            if target:
                return self._line(
                    "🎯", "Connected to ", (conn.name, "bold"), f" at {conn.describe_peer()}", style="green"
                )
            named = f" ({conn.name})" if conn.name else ""
            return self._line("🔗", f"Connected to {conn.describe_peer()}{named}", style="dim")
        if ev.kind is Ev.CONNECT_FAILED:
            return self._line("⛔", f"Connection to {ev.addr} failed, status 0x{ev.code:02X}", style="dim")
        if ev.kind is Ev.DISCONNECTED:
            if not interesting:
                return None
            reason = HCI_REASONS.get(ev.code, f"reason 0x{ev.code:02X}")
            return self._line("👋", f"{conn.label} disconnected ({reason})", style="dim")
        if ev.kind is Ev.NAMED:
            if target:
                return self._line(
                    "🎯",
                    f"{conn.peer or 'The connection'} is ",
                    (conn.name, "bold"),
                    f" (from its {conn.name_source})",
                    style="green",
                )
            return self._line("📛", f"{conn.peer} is {conn.name} ({conn.name_source})", style="dim")
        if ev.kind is Ev.SECURITY_REQUEST:
            return self._line("🔐", f"{self._who(conn, ev.from_phone)} asks to pair")
        if ev.kind is Ev.PAIRING_REQUEST:
            req = conn.request
            asker = "the iPhone" if ev.from_phone else conn.label
            other = conn.label if ev.from_phone else "the iPhone"
            return self._line(
                "🤝",
                ("Pairing Request", "bold"),
                f" from {asker} ({IO_CAPABILITIES.get(req[1], f'IO 0x{req[1]:02X}')}): it offers "
                f"{key_dist(req[5])} and asks {other} for {key_dist(req[6])}",
            )
        if ev.kind is Ev.PAIRING_RESPONSE:
            rsp = conn.response
            peer_keys = conn.peer_keys() or 0
            phone_keys = rsp[5] if conn.request_from_phone else rsp[6]
            method = pairing_method(conn.request, rsp) if conn.request else "pairing"
            return self._line(
                "🤝",
                ("Pairing Response", "bold"),
                f" from {self._who(conn, ev.from_phone)} ({IO_CAPABILITIES.get(rsp[1], f'IO 0x{rsp[1]:02X}')}): "
                f"{method}. {conn.label} will send {key_dist(peer_keys)}, the iPhone {key_dist(phone_keys)}",
            )
        if ev.kind is Ev.PUBLIC_KEY:
            return self._line("🔄", "Exchanging public keys (LE Secure Connections)", style="dim")
        if ev.kind is Ev.PAIRING_FAILED:
            name, tip = SMP_FAILURES.get(ev.code, (f"reason 0x{ev.code:02X}", ""))
            who = "the iPhone" if ev.from_phone else conn.label
            line = self._line("❌", ("Pairing failed", "bold"), f": {name} (reported by {who})", style="red")
            if tip:
                line.append(f"\n{tip}", "yellow")
            return line
        if ev.kind is Ev.ENCRYPTED:
            if not interesting:
                return None
            if conn.smp:
                return self._line("🔒", f"Link to {conn.label} encrypted with the new keys")
            line = self._line("🔒", f"Link to {conn.label} encrypted with keys from an existing bond")
            if target and not conn.peer_irk and not self.bond_hint_shown:
                self.bond_hint_shown = True
                line.append(
                    f"\nThe iPhone still remembers {conn.name}. Forget it in Settings → Bluetooth "
                    "first: keys only travel while pairing.",
                    "yellow",
                )
            return line
        if ev.kind is Ev.ENCRYPTION_FAILED:
            if not interesting:
                return None
            hint = " (the device lost its bond: forget it on the iPhone and pair again)" if ev.code == 0x06 else ""
            return self._line("❌", f"Encrypting {conn.label} failed, status 0x{ev.code:02X}{hint}", style="red")
        if ev.kind is Ev.IRK:
            if ev.from_phone:
                return self._line("🔑", "The iPhone sent its own IRK", style="dim")
            line = self._line("🔑", (f"{conn.label} sent its IRK", "bold magenta"))
            hits = [a for a in conn.addresses() if resolves(conn.peer_irk, a)]
            if hits:
                line.append(f" (resolves {', '.join(hits)} ✓)", "green")
            return line
        if ev.kind is Ev.IDENTITY:
            who = "iPhone" if ev.from_phone else conn.label
            identity = conn.phone_identity if ev.from_phone else conn.peer_identity
            return self._line("📍", f"{who}'s identity address: {identity}", style="" if not ev.from_phone else "dim")
        if ev.kind is Ev.OTHER_KEY:
            return self._line("📦", f"{self._who(conn, ev.from_phone)} sent {SMP_NAMES[ev.code]}", style="dim")
        return None

    def _warn_no_idkey(self, conn: Conn) -> None:
        keys = conn.peer_keys()
        if keys is None or keys & KEY_ID:
            return
        self.console.print(
            Panel(
                Text.assemble(
                    (conn.label, "bold"),
                    f" only distributes {key_dist(keys)}, no IdKey, so it will never send an IRK.\n",
                    "Devices that don't hand out an IRK don't use resolvable private addresses: track "
                    f"its address ({conn.describe_peer()}) directly instead.",
                ),
                title="⚠ No IRK coming",
                border_style="yellow",
            )
        )


# --- Results --------------------------------------------------------------------------------


def ha_formats(irk: bytes) -> tuple[str, str]:
    """Home Assistant takes hex as the AES key (MSB first) and reverses base64 input."""
    return irk.hex(), base64.b64encode(bytes(reversed(irk))).decode()


def show_result(console: Console, tracker: Tracker, conn: Conn) -> None:
    hex_irk, b64_irk = ha_formats(conn.peer_irk)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right")
    grid.add_column()
    name = Text(conn.name or "(no name seen)", style="bold")
    if conn.name_source:
        name.append(f"  matched by {conn.name_source}", "dim")
    grid.add_row("Device", name)
    grid.add_row("Paired from", conn.describe_peer())
    grid.add_row("Identity address", conn.peer_identity or "not sent")
    grid.add_row("IRK (hex)", Text(hex_irk, style="bold magenta"))
    grid.add_row("IRK (base64)", Text(b64_irk, style="magenta"))
    checks = [a for a in conn.addresses() if is_rpa(a)]
    if checks:
        for addr in checks:
            ok = resolves(conn.peer_irk, addr)
            grid.add_row(
                "Check",
                Text(
                    f"{'✓' if ok else '✗'} ah(IRK, {addr[:8]}) {'=' if ok else '≠'} {addr[9:]}: "
                    f"{'resolves' if ok else 'does NOT resolve'} {addr}",
                    style="green" if ok else "red",
                ),
            )
    else:
        grid.add_row("Check", Text("no resolvable private address in this pairing to test against", style="yellow"))
    if not any(conn.peer_irk):
        grid.add_row("", Text("All zeros: this device doesn't really use privacy.", style="yellow"))
    if conn.phone_irk:
        grid.add_row("", "")
        grid.add_row("iPhone's IRK (hex)", conn.phone_irk.hex())
        grid.add_row("iPhone's IRK (base64)", ha_formats(conn.phone_irk)[1])
        grid.add_row("iPhone's identity", conn.phone_identity or "not sent")
    console.print(Panel(grid, title=Text(f"🎉 IRK for {conn.label}"), border_style="green", padding=(1, 2)))
    console.print(
        Panel(
            Text.assemble(
                "In Home Assistant: ",
                ("Settings → Devices & services → Add integration → Private BLE Device", "bold"),
                ", then paste the IRK (hex or base64, both work).\n"
                "The iPhone's own IRK works the same way if you want to track the phone itself.",
            ),
            title="🏠 Next",
            border_style="blue",
        )
    )


def pick_results(console: Console, tracker: Tracker, interactive: bool) -> list[Conn]:
    peers = tracker.paired_peers()
    matched = [c for c in peers if tracker.is_target(c)]
    if len(matched) == 1:
        return matched
    pool = matched or peers
    if not pool:
        return []
    if tracker.target and not matched:
        console.print(
            Text(
                f"Couldn't tie any pairing to “{tracker.target}”: no name or advert linked it to a connection.",
                style="yellow",
            )
        )
    elif matched:
        console.print(Text(f"{len(matched)} pairings match “{tracker.target}”.", style="yellow"))
    if len(pool) == 1 and not tracker.target:
        return pool
    table = Table(title="Devices that sent an IRK", title_style="bold", header_style="dim")
    for column in ("#", "Paired", "Address", "Identity address", "Name"):
        table.add_column(column)
    for i, conn in enumerate(pool, 1):
        table.add_row(str(i), clock(conn.started), conn.describe_peer(), conn.peer_identity or "", conn.name or "")
    console.print(table)
    if not interactive:
        return pool
    choice = Prompt.ask("Which one is it?", choices=[str(i) for i in range(1, len(pool) + 1)], default="1")
    return [pool[int(choice) - 1]]


def show_no_result(console: Console, tracker: Tracker, session: Session) -> None:
    if session.no_irk:
        conn = session.no_irk
        console.print(
            Panel(
                f"{conn.label} paired but never sent an IRK (it only distributes "
                f"{key_dist(conn.peer_keys() or 0)}). Track it by its address instead: "
                f"{conn.describe_peer()}.",
                title="No IRK to extract",
                border_style="yellow",
            )
        )
        return
    tips = ["Make sure you Forget the device on the iPhone first, then pair it again: keys only travel while pairing."]
    if not tracker.hci_records:
        tips.append("No Bluetooth traffic at all means the logging profile isn't active.")
    if tracker.target and not any(tracker.is_target(c) for c in tracker.conns):
        tips.insert(0, f"Nothing called “{tracker.target}” connected. Check the name the iPhone shows for it.")
    console.print(Panel("\n".join(f"• {t}" for t in tips), title="No IRK captured", border_style="yellow"))


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def summarize(console: Console, tracker: Tracker) -> None:
    hidden = tracker.cancelled_connects
    note = f", hid {plural(hidden, 'cancelled background connect')}" if hidden else ""
    console.print(
        Text(f"{plural(tracker.records, 'record')}, {plural(len(tracker.conns), 'connection')}{note}", style="dim")
    )


# --- Replay ---------------------------------------------------------------------------------


def replay(console: Console, path: Path, target: str | None, interactive: bool) -> int:
    if not path.is_file():
        raise SetupError(f"No such file: {path}")
    if target is None and interactive:
        target = Prompt.ask("Device name to look for [dim](Enter to list every device that paired)[/]", default="")
    found = 0
    for name, data in read_traces(path):
        console.rule(Text(f"Replaying {name}", style="bold"), align="left", style="dim")
        tracker = Tracker(target)
        session = Session(tracker)
        narrator = Narrator(console, tracker)
        try:
            records = PklgReader().feed(data)
        except TraceError as e:
            raise SetupError(f"{name}: {e}") from e
        for rec in records:
            events = tracker.feed(rec)
            for ev in events:
                narrator.show(ev)
            if tracker.target:
                session.update(events, rec.ts)
                if session.done(rec.ts):
                    break
        summarize(console, tracker)
        results = pick_results(console, tracker, interactive)
        for conn in results:
            show_result(console, tracker, conn)
        if not results:
            show_no_result(console, tracker, session)
        found += len(results)
    return 0 if found else 1


# --- iPhone over USB ------------------------------------------------------------------------


def pmd3_command() -> list[str]:
    if override := os.environ.get("IRK_EXTRACT_PMD3"):
        return shlex.split(override)
    if importlib.util.find_spec("pymobiledevice3"):
        return [sys.executable, "-m", "pymobiledevice3"]
    if exe := shutil.which("pymobiledevice3"):
        return [exe]
    if uvx := shutil.which("uvx"):
        return [uvx, "--from", PMD3_REQUIREMENT, "pymobiledevice3"]
    raise SetupError(
        "pymobiledevice3 isn't installed. Install uv (https://docs.astral.sh/uv/) and I'll run it "
        "through uvx, or `pipx install pymobiledevice3`."
    )


def last_line(output: str) -> str:
    """pymobiledevice3's own ERROR message if it logged one, else the last line of output."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    errors = [line.split(" ERROR ", 1)[1] for line in lines if " ERROR " in line]
    if errors:
        return errors[-1]
    return lines[-1] if lines else "no output"


class Phone:
    def __init__(self, command: list[str], udid: str | None = None) -> None:
        self.command = command
        self.udid = udid

    def argv(self, *args: str, device: bool = True) -> list[str]:
        argv = [*self.command, "--no-color", *args]
        if device and self.udid:
            argv += ["--udid", self.udid]
        return argv

    def run(self, *args: str, device: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.argv(*args, device=device),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def json(self, *args: str, device: bool = True) -> object:
        result = self.run(*args, device=device)
        if result.returncode:
            raise SetupError(f"pymobiledevice3 {' '.join(args)} failed: {last_line(result.stderr + result.stdout)}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise SetupError(f"pymobiledevice3 {' '.join(args)} printed something unexpected") from e

    def devices(self) -> list[dict]:
        return [d for d in self.json("usbmux", "list", device=False) if d.get("ConnectionType") == "USB"]

    def logging_profile(self) -> str | None:
        profiles = self.json("profile", "list") or {}
        metadata = profiles.get("ProfileMetadata") or {}
        for identifier, meta in metadata.items():
            display = str(meta.get("PayloadDisplayName", "")).lower()
            if identifier == PROFILE_ID or "bluetooth.logging" in identifier or "bluetooth logging" in display:
                return identifier
        return None

    def install_profile(self, path: Path) -> None:
        result = self.run("profile", "install", str(path))
        if result.returncode:
            raise SetupError(f"Installing the profile failed: {last_line(result.stderr + result.stdout)}")

    def remove_profile(self, identifier: str) -> bool:
        return self.run("profile", "remove", identifier).returncode == 0


class Capture:
    """``pymobiledevice3 btlogger FILE`` in its own process group, followed as the file grows."""

    def __init__(self, phone: Phone, path: Path) -> None:
        self.phone = phone
        self.path = path
        self.proc: subprocess.Popen | None = None
        self.log: deque[str] = deque(maxlen=50)
        self.size = 0
        self._fh: io.BufferedReader | None = None

    def start(self) -> None:
        os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        self.proc = subprocess.Popen(
            self.phone.argv("btlogger", str(self.path)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        for line in self.proc.stdout:
            self.log.append(line.decode("utf-8", "replace").rstrip())

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def read(self) -> bytes:
        if self._fh is None:
            try:
                self._fh = open(self.path, "rb")  # noqa: SIM115
            except FileNotFoundError:
                return b""
        data = self._fh.read()
        self.size += len(data)
        return data

    def last_error(self) -> str:
        return last_line("\n".join(self.log))

    def stop(self) -> None:
        if self.running:
            for sig, wait in ((signal.SIGINT, 5), (signal.SIGTERM, 3), (signal.SIGKILL, 3)):
                try:
                    os.killpg(self.proc.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    self.proc.wait(wait)
                    break
                except subprocess.TimeoutExpired:
                    continue
        if self._fh:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> Capture:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


# --- Guided flow ----------------------------------------------------------------------------


def step(console: Console, number: int, title: str) -> None:
    console.print()
    console.rule(Text.assemble((f"{number}", "bold cyan"), "  ", (title, "bold")), align="left", style="dim")


def ok(console: Console, *parts: str | tuple[str, str]) -> None:
    console.print(Text.assemble(("✓ ", "green"), *parts))


def install_hint() -> str:
    for manager, command in (
        ("pacman", "sudo pacman -S --needed usbmuxd"),
        ("apt-get", "sudo apt install usbmuxd"),
        ("dnf", "sudo dnf install usbmuxd"),
        ("zypper", "sudo zypper install usbmuxd"),
    ):
        if shutil.which(manager):
            return command
    return "install usbmuxd with your package manager"


def usbmuxd_reachable() -> bool:
    for path in USBMUXD_SOCKETS:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                sock.connect(path)
                return True
            except OSError:
                continue
    return False


def usbmuxd_problem() -> str | None:
    if sys.platform == "darwin" or os.environ.get("USBMUXD_SOCKET_ADDRESS"):
        return None
    if not (shutil.which("usbmuxd") or Path("/usr/sbin/usbmuxd").exists() or Path("/usr/bin/usbmuxd").exists()):
        return "missing"
    if not usbmuxd_reachable():
        return "stopped"
    return None


def check_usbmuxd(console: Console) -> None:
    problem = usbmuxd_problem()
    if problem == "missing":
        raise SetupError(
            "usbmuxd isn't installed. It's the daemon that talks to iPhones over USB. Run this "
            f"yourself, then replug the iPhone and start irk-extract again:\n\n    {install_hint()}"
        )
    if problem == "stopped":
        console.print(
            Panel(
                "usbmuxd isn't running. udev starts it when an iPhone is plugged in (and stops it "
                "when the last one leaves), so plug the iPhone in, or unplug it and plug it back in.\n"
                "If it still doesn't start, run [bold]sudo systemctl start usbmuxd[/] yourself.",
                border_style="yellow",
            )
        )
        with console.status("Waiting for usbmuxd, plug the iPhone in…"):
            while usbmuxd_problem():
                time.sleep(1)
    ok(console, "usbmuxd is running")


def wait_for_iphone(console: Console, phone: Phone) -> dict:
    with console.status("Looking for an iPhone on USB…") as status:
        while True:
            try:
                devices = phone.devices()
            except SetupError:
                devices = []
            if phone.udid:
                devices = [d for d in devices if phone.udid in (d.get("Identifier"), d.get("UniqueDeviceID"))]
            if devices:
                break
            status.update("Plug the iPhone in with a cable and unlock it…")
            time.sleep(2)
    device = devices[0]
    if len(devices) > 1:
        for i, d in enumerate(devices, 1):
            console.print(
                Text(f"  {i}. {d.get('DeviceName', '?')} ({d.get('ProductType', '?')}, {d.get('Identifier')})")
            )
        choice = Prompt.ask("Which iPhone?", choices=[str(i) for i in range(1, len(devices) + 1)], default="1")
        device = devices[int(choice) - 1]
    phone.udid = device.get("Identifier") or device.get("UniqueDeviceID")
    ok(
        console,
        "Found ",
        (str(device.get("DeviceName", "an iPhone")), "bold"),
        f" ({device.get('ProductType', '?')}, iOS {device.get('ProductVersion', '?')})",
    )
    return device


def ensure_trusted(console: Console, phone: Phone) -> None:
    while True:
        proc = subprocess.Popen(
            phone.argv("lockdown", "device-name"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        started = time.monotonic()
        with console.status("Checking that the iPhone trusts this computer…") as status:
            while proc.poll() is None:
                if time.monotonic() - started > 3:
                    status.update("If the iPhone asks [bold]Trust This Computer?[/], tap Trust and enter the passcode…")
                time.sleep(0.2)
        output = proc.stdout.read()
        if proc.returncode == 0:
            ok(console, "The iPhone trusts this computer")
            return
        lowered = output.lower()
        if "passcode" in lowered or "password" in lowered:
            console.print("[yellow]The iPhone is locked.[/] Unlock it, keep it on the home screen.")
        elif "refuse" in lowered or "denied" in lowered:
            console.print(
                "[yellow]The iPhone said Don't Trust.[/] Unplug it and plug it back in to get the prompt again."
            )
        else:
            raise SetupError(f"Couldn't pair with the iPhone: {last_line(output)}")
        Prompt.ask("Press Enter to try again", default="", show_default=False)


def ask_profile_path(console: Console) -> Path | None:
    while True:
        raw = Prompt.ask(
            "Path to [bold]iOSBluetoothLogging.mobileconfig[/] "
            "[dim](or Enter if you installed it on the iPhone yourself)[/]",
            default="",
            show_default=False,
        ).strip()
        if not raw:
            return None
        path = Path(raw.strip("'\"")).expanduser()
        if not path.is_file():
            console.print(Text(f"No file at {path}", style="red"))
            continue
        data = path.read_bytes()
        looks_right = len(data) < 1_000_000 and b"bluetooth" in data.lower()
        if looks_right or Confirm.ask(
            "That doesn't look like Apple's Bluetooth logging profile. Install it anyway?", default=False
        ):
            return path


def ensure_profile(console: Console, phone: Phone, profile: Path | None) -> tuple[str, bool]:
    with console.status("Looking for Apple's Bluetooth logging profile…"):
        identifier = phone.logging_profile()
    if identifier:
        ok(console, "The Bluetooth logging profile is installed")
        return identifier, False
    console.print(
        Panel(
            Text.assemble(
                "The iPhone only logs Bluetooth traffic with Apple's ",
                ("Bluetooth for iOS", "bold"),
                " logging profile. Apple hands it out after an Apple ID sign-in, so irk-extract can't "
                "download or ship it for you:\n\n",
                "  1. Open ",
                (PROFILE_PAGE, "link " + PROFILE_PAGE),
                " and sign in\n",
                "  2. Download the Bluetooth for iOS profile (",
                ("iOSBluetoothLogging.mobileconfig", "bold"),
                ")\n  3. Give me its path below, and I'll send it to the iPhone over USB",
            ),
            title="📄 Logging profile needed",
            border_style="cyan",
        )
    )
    while True:
        path = profile or ask_profile_path(console)
        profile = None
        if path is not None:
            with console.status("Sending the profile to the iPhone…"):
                phone.install_profile(path)
        with console.status("Checking the iPhone…"):
            identifier = phone.logging_profile()
        if identifier:
            break
        if path is None:
            console.print("[yellow]Still no logging profile on the iPhone.[/]")
            continue
        console.print(
            Panel(
                Text.assemble(
                    "iOS wants you to confirm the profile on the iPhone itself:\n\n",
                    "  1. Open ",
                    ("Settings", "bold"),
                    " and tap ",
                    ("Profile Downloaded", "bold"),
                    " near the top\n     (or General → VPN & Device Management)\n",
                    "  2. Tap ",
                    ("Install", "bold"),
                    ", enter the passcode, then ",
                    ("Install", "bold"),
                    " again\n\n",
                    ("iOS discards a downloaded profile after 8 minutes.", "dim"),
                ),
                title="📲 On the iPhone",
                border_style="cyan",
            )
        )
        deadline = time.monotonic() + 8 * 60
        with console.status("Waiting for you to install it on the iPhone…"):
            while not (identifier := phone.logging_profile()) and time.monotonic() < deadline:
                time.sleep(2)
        if identifier:
            break
        console.print("[yellow]The profile never got installed, so iOS discarded it. Let's try again.[/]")
    ok(console, "Bluetooth logging profile installed")
    return identifier, True


def repair_instructions(target: str) -> Panel:
    return Panel(
        Text.assemble(
            "Now re-pair ",
            (target, "bold"),
            ":\n\n  1. On the iPhone: Settings → Bluetooth → ⓘ next to ",
            (target, "bold"),
            " → ",
            ("Forget This Device", "bold"),
            "\n  2. Pair it again from its own app (or from Settings → Bluetooth)\n\n",
            ("Keys are only exchanged while pairing, so a plain reconnect isn't enough. ", "dim"),
            ("I'll narrate as it happens. Ctrl-C stops.", "dim"),
        ),
        title="🔁 Re-pair the device",
        border_style="cyan",
    )


def capture_status(cap: Capture, tracker: Tracker, rate: float, target: str) -> str:
    hidden = tracker.cancelled_connects
    note = f" · {plural(hidden, 'background connect')} hidden" if hidden else ""
    return (
        f"Listening for [bold]{escape(target)}[/] · {cap.size // 1024} KB · {rate:.1f} KB/s · "
        f"{plural(len(tracker.conns), 'connection')}{note}"
    )


def follow_capture(console: Console, cap: Capture, tracker: Tracker, session: Session) -> bool:
    """Narrate the live capture until the session is done. Returns False on Ctrl-C."""
    narrator = Narrator(console, tracker)
    reader = PklgReader()
    samples: deque[tuple[float, int]] = deque(maxlen=40)

    def pump() -> None:
        chunk = cap.read()
        now = time.monotonic()
        samples.append((now, cap.size))
        try:
            records = reader.feed(chunk)
        except TraceError as e:
            raise SetupError(f"The capture isn't a PacketLogger stream: {e}") from e
        for rec in records:
            events = tracker.feed(rec)
            for ev in events:
                narrator.show(ev)
            session.update(events, now)

    def rate() -> float:
        if len(samples) < 2 or samples[-1][0] - samples[0][0] < 0.5:
            return 0.0
        return (samples[-1][1] - samples[0][1]) / 1024 / (samples[-1][0] - samples[0][0])

    try:
        with console.status("Starting the Bluetooth capture…") as status:
            cap.start()
            started = time.monotonic()
            warned = False
            while not tracker.hci_records:
                pump()
                if not cap.running:
                    raise SetupError(f"The capture stopped: {cap.last_error()}")
                if not warned and time.monotonic() - started > 15:
                    warned = True
                    console.print(
                        Panel(
                            f"Nothing yet after 15 seconds ({cap.size} bytes). That's what happens when the "
                            "logging profile isn't active: check Settings → General → VPN & Device Management "
                            "lists Bluetooth Logging, then toggle Bluetooth off and on, or restart the iPhone. "
                            "I'll keep waiting.",
                            border_style="yellow",
                        )
                    )
                time.sleep(0.25)
            ok(console, "Bluetooth traffic is flowing")
            console.print(repair_instructions(tracker.target))
            while not session.done(time.monotonic()):
                pump()
                status.update(capture_status(cap, tracker, rate(), tracker.target))
                if not cap.running:
                    pump()
                    console.print(Text(f"The capture stopped unexpectedly: {cap.last_error()}", style="red"))
                    break
                time.sleep(0.2)
            pump()
    except KeyboardInterrupt:
        return False
    finally:
        cap.stop()
    return True


def offer_profile_removal(console: Console, phone: Phone, identifier: str, installed_now: bool) -> None:
    if not Confirm.ask("Remove the Bluetooth logging profile from the iPhone now?", default=installed_now):
        console.print("[dim]Keeping it. Remove it later in Settings → General → VPN & Device Management.[/]")
        return
    with console.status("Removing the profile…"):
        phone.remove_profile(identifier)
        still_there = phone.logging_profile()
    if still_there:
        console.print(
            "[yellow]iOS kept the profile.[/] Remove it in Settings → General → VPN & Device Management "
            "→ Bluetooth Logging for iOS → Remove Profile."
        )
    else:
        ok(console, "Profile removed")


def live(console: Console, args: argparse.Namespace) -> int:
    step(console, 1, "Preflight")
    check_usbmuxd(console)
    phone = Phone(pmd3_command(), args.udid)
    wait_for_iphone(console, phone)
    ensure_trusted(console, phone)

    step(console, 2, "Bluetooth logging profile")
    identifier, installed_now = ensure_profile(console, phone, args.profile)

    step(console, 3, "Which device?")
    target = (args.name or "").strip()
    while not target:
        target = Prompt.ask(
            "Bluetooth name of the device, as the iPhone shows it [dim](e.g. Google Fitbit Air)[/]"
        ).strip()
    ok(console, "Looking for ", (target, "bold"))

    step(console, 4, "Capture and re-pair")
    out = args.out or Path.cwd() / f"irk-capture-{time.strftime('%Y%m%d-%H%M%S')}.pklg"
    tracker = Tracker(target)
    session = Session(tracker)
    with Capture(phone, out) as cap:
        finished = follow_capture(console, cap, tracker, session)
    ok(console, "Capture stopped, saved to ", (str(out), "bold"))
    if not finished:
        console.print("[yellow]Stopped early.[/]")

    step(console, 5, "Result")
    summarize(console, tracker)
    results = pick_results(console, tracker, interactive=True)
    for conn in results:
        show_result(console, tracker, conn)
    if not results:
        show_no_result(console, tracker, session)
    console.print(
        Text(
            "The capture holds this iPhone's Bluetooth keys. Keep it private, or delete it: "
            f"rm {shlex.quote(str(out))}",
            style="dim",
        )
    )

    step(console, 6, "Clean up")
    offer_profile_removal(console, phone, identifier, installed_now)
    if results:
        return 0
    return 130 if not finished else 1


def banner(console: Console) -> None:
    console.print(
        Panel(
            Text.assemble(
                ("irk-extract", "bold cyan"),
                f" {__version__}\n",
                "Gets a Bluetooth device's Identity Resolving Key out of your iPhone's bond, over USB, "
                "so Home Assistant can follow it through its private addresses.",
            ),
            border_style="cyan",
            padding=(1, 2),
        )
    )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="irk-extract",
        description="Get a Bluetooth LE device's IRK out of an iPhone bond by capturing the "
        "iPhone's HCI traffic over USB while the device re-pairs.",
    )
    parser.add_argument("--name", help="Bluetooth name of the device, as the iPhone shows it")
    parser.add_argument(
        "--profile", type=Path, help="Apple's iOSBluetoothLogging.mobileconfig, if it isn't installed yet"
    )
    parser.add_argument("--out", type=Path, help="where to save the capture (default: ./irk-capture-<time>.pklg)")
    parser.add_argument("--udid", help="which iPhone, if more than one is plugged in")
    parser.add_argument(
        "--replay", type=Path, metavar="FILE", help="narrate a saved .pklg (or sysdiagnose .tar.gz) instead"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    console = Console(highlight=False)
    try:
        if args.replay:
            return replay(console, args.replay, args.name, interactive=sys.stdin.isatty())
        banner(console)
        return live(console, args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/]")
        return 130
    except EOFError:
        console.print("\n[yellow]No more input, stopping.[/]")
        return 130
    except SetupError as e:
        console.print(Panel(Text(str(e)), title="Can't continue", border_style="red"))
        return 2


if __name__ == "__main__":
    sys.exit(main())
