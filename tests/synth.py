"""Synthetic PacketLogger traces. Every key, address and name in here is made up."""

from __future__ import annotations

import struct

import irk_extract as ie

BAND_NAME = "Test Band"
BAND_IRK = bytes.fromhex("00112233445566778899aabbccddeeff")
BAND_IDENTITY = "C0:FF:EE:12:34:56"
PHONE_IRK = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
PHONE_IDENTITY = "F0:0D:F0:0D:00:01"
OTHER_IRK = bytes.fromhex("ffeeddccbbaa99887766554433221100")
OLD_BOND = "D0:0D:D0:0D:00:02"


def le(addr: str) -> bytes:
    return ie.addr_bytes_le(addr)


def rpa_for(irk: bytes, prand: bytes = b"\x51\x13\x7d") -> str:
    prand = bytes([(prand[0] & 0x3F) | 0x40]) + prand[1:]
    return ie.fmt_addr(bytes(reversed(prand + ie.ah(irk, prand))))


BAND_RPA = rpa_for(BAND_IRK)
OTHER_RPA = rpa_for(OTHER_IRK, b"\x22\x33\x44")


class Trace:
    def __init__(self, order: str = ">", start: float = 1_800_000_000.0) -> None:
        self.order = order
        self.t = start
        self.chunks: list[bytes] = []

    def record(self, kind: int, payload: bytes, dt: float = 0.01) -> Trace:
        self.t += dt
        secs = int(self.t)
        usecs = round((self.t - secs) * 1e6)
        header = struct.pack(self.order + "III", 9 + len(payload), secs, usecs)
        self.chunks.append(header + bytes([kind]) + payload)
        return self

    def note(self, text: str) -> Trace:
        return self.record(ie.PKLG_NOTE, text.encode())

    def phone_header(self) -> Trace:
        self.note("Product: iPhone99,1")
        self.note("Chipset: Test Chip, Revision: A0")
        return self.note("Software: Version 99.0 (Build 99A1)")

    def event(self, code: int, params: bytes, dt: float = 0.01) -> Trace:
        return self.record(ie.PKLG_EVENT, bytes([code, len(params)]) + params, dt)

    def idle(self, seconds: float = 6.0) -> Trace:
        for _ in range(int(seconds)):
            self.event(0x13, b"\x01\x40\x00\x01\x00", dt=1.0)
        return self

    def connect(
        self,
        handle: int,
        peer: str,
        peer_type: int = 1,
        peer_rpa: str | None = None,
        status: int = 0,
    ) -> Trace:
        params = (
            bytes([status])
            + struct.pack("<H", handle)
            + bytes([0, peer_type])
            + le(peer)
            + bytes(6)
            + (le(peer_rpa) if peer_rpa else bytes(6))
            + struct.pack("<HHH", 24, 0, 500)
            + b"\x00"
        )
        return self.event(0x3E, bytes([0x0A]) + params)

    def cancelled_connect(self) -> Trace:
        return self.connect(0x0FFF, "00:00:00:00:00:00", peer_type=0, status=0x02)

    def disconnect(self, handle: int, reason: int = 0x13) -> Trace:
        return self.event(0x05, bytes([0]) + struct.pack("<H", handle) + bytes([reason]))

    def encrypted(self, handle: int, status: int = 0) -> Trace:
        return self.event(0x59, bytes([status]) + struct.pack("<H", handle) + bytes([1, 16]))

    def acl(self, handle: int, cid: int, pdu: bytes, sent: bool, split: int | None = None) -> Trace:
        frame = struct.pack("<HH", len(pdu), cid) + pdu
        parts = [frame] if split is None else [frame[:split], frame[split:]]
        for i, part in enumerate(parts):
            flags = handle | ((0b10 if i == 0 else 0b01) << 12)
            kind = ie.PKLG_ACL_SENT if sent else ie.PKLG_ACL_RECV
            self.record(kind, struct.pack("<HH", flags, len(part)) + part)
        return self

    def att(self, handle: int, pdu: bytes, sent: bool) -> Trace:
        return self.acl(handle, ie.L2CAP_ATT, pdu, sent)

    def smp(self, handle: int, pdu: bytes, sent: bool, split: int | None = None) -> Trace:
        return self.acl(handle, ie.L2CAP_SMP, pdu, sent, split)

    def gatt_name(self, handle: int, name: str) -> Trace:
        self.att(handle, bytes([0x08]) + struct.pack("<HHH", 1, 9, ie.UUID_DEVICE_NAME), sent=True)
        value = name.encode()
        return self.att(handle, bytes([0x09, 2 + len(value)]) + struct.pack("<H", 3) + value, sent=False)

    def gatt_name_by_discovery(self, handle: int, name: str) -> Trace:
        self.att(handle, bytes([0x08]) + struct.pack("<HHH", 1, 9, ie.UUID_CHARACTERISTIC), sent=True)
        decl = struct.pack("<HBHH", 2, 0x02, 3, ie.UUID_DEVICE_NAME)
        self.att(handle, bytes([0x09, len(decl)]) + decl, sent=False)
        self.att(handle, bytes([0x0A]) + struct.pack("<H", 3), sent=True)
        return self.att(handle, bytes([0x0B]) + name.encode(), sent=False)

    def apple_scan(self, addr: str, name: str) -> Trace:
        """Shaped like the vendor (0xFF) events iOS logs for each scan result."""
        ad = bytes([len(name) + 1, 0x09]) + name.encode() + bytes([2, 1, 6])
        params = (
            bytes([0x0E, 0x0A, 0x04, 0x01, 0x18, 0x26, 0x01])
            + le(addr)
            + bytes([0x81, 0x00, 0xFF, 0x7F])
            + bytes(10)
            + bytes([len(ad)])
            + ad
            + bytes(8)
        )
        return self.event(0xFF, params)

    def adv_report(self, addr: str, name: str, addr_type: int = 1) -> Trace:
        ad = bytes([len(name) + 1, 0x09]) + name.encode()
        params = bytes([0x02, 1, 0, addr_type]) + le(addr) + bytes([len(ad)]) + ad + bytes([0xC8])
        return self.event(0x3E, params)

    def pairing(
        self,
        handle: int,
        peer_irk: bytes,
        peer_identity: str,
        responder_keys: int = 0x03,
        split_irk: bool = False,
        fail: int | None = None,
    ) -> Trace:
        self.smp(handle, bytes([0x01, 0x04, 0x00, 0x2D, 0x10, 0x0B, 0x0B]), sent=True)
        self.smp(handle, bytes([0x02, 0x03, 0x00, 0x0D, 0x10, 0x02, responder_keys]), sent=False)
        self.smp(handle, bytes([0x0C]) + bytes(64), sent=True)
        self.smp(handle, bytes([0x0C]) + bytes(64), sent=False)
        if fail is not None:
            return self.smp(handle, bytes([0x05, fail]), sent=False)
        for op, sent in ((0x03, False), (0x04, True), (0x04, False), (0x0D, True), (0x0D, False)):
            self.smp(handle, bytes([op]) + bytes(16), sent=sent)
        self.encrypted(handle)
        if responder_keys & ie.KEY_ID:
            self.smp(handle, bytes([0x08]) + bytes(reversed(peer_irk)), sent=False, split=6 if split_irk else None)
            self.smp(handle, bytes([0x09, 0x01]) + le(peer_identity), sent=False)
        self.smp(handle, bytes([0x08]) + bytes(reversed(PHONE_IRK)), sent=True)
        return self.smp(handle, bytes([0x09, 0x00]) + le(PHONE_IDENTITY), sent=True)

    def data(self) -> bytes:
        return b"".join(self.chunks)


def band_repair(
    order: str = ">",
    name_via: str = "gatt",
    responder_keys: int = 0x03,
    split_irk: bool = False,
    old_bond: bool = True,
) -> Trace:
    """A re-pair like the one iOS logs: background noise, the band connecting from an RPA, SMP."""
    t = Trace(order).phone_header()
    for _ in range(3):
        t.cancelled_connect()
    if name_via == "apple":
        t.apple_scan(BAND_RPA, BAND_NAME)
    elif name_via == "adv":
        t.adv_report(BAND_RPA, BAND_NAME)
    if old_bond:
        t.connect(0x40, OLD_BOND, peer_type=0).encrypted(0x40)
    t.connect(0x41, BAND_RPA)
    if name_via == "gatt":
        t.gatt_name(0x41, BAND_NAME)
    elif name_via == "discovery":
        t.gatt_name_by_discovery(0x41, BAND_NAME)
    t.pairing(0x41, BAND_IRK, BAND_IDENTITY, responder_keys=responder_keys, split_irk=split_irk)
    return t.idle().disconnect(0x41, 0x16)
