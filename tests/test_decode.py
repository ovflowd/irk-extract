import base64
import io
import tarfile

import pytest

import irk_extract as ie
import synth


def track(trace: synth.Trace, target: str | None = synth.BAND_NAME):
    tracker = ie.Tracker(target)
    events = []
    for rec in ie.PklgReader().feed(trace.data()):
        events += tracker.feed(rec)
    return tracker, events


def test_ah_matches_the_core_spec_vector():
    # Bluetooth Core spec, Vol 3 Part H, D.7
    irk = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
    assert ie.ah(irk, bytes.fromhex("708194")) == bytes.fromhex("0dfbaa")
    assert ie.resolves(irk, "70:81:94:0D:FB:AA")
    assert not ie.resolves(irk, "70:81:94:0D:FB:AB")


def test_only_resolvable_private_addresses_resolve():
    assert ie.resolves(synth.BAND_IRK, synth.BAND_RPA)
    assert not ie.resolves(synth.BAND_IRK, synth.BAND_IDENTITY)
    assert ie.random_kind(synth.BAND_RPA) == "resolvable private"
    assert ie.random_kind(synth.BAND_IDENTITY) == "random static"


def test_home_assistant_formats():
    hex_irk, b64_irk = ie.ha_formats(synth.BAND_IRK)
    assert hex_irk == synth.BAND_IRK.hex()
    assert bytes(reversed(base64.b64decode(b64_irk))) == synth.BAND_IRK


@pytest.mark.parametrize("order", [">", "<"])
def test_reader_handles_both_byte_orders_and_any_chunking(order):
    data = synth.band_repair(order).data()
    whole = ie.PklgReader().feed(data)
    reader = ie.PklgReader()
    trickled = [rec for i in range(0, len(data), 7) for rec in reader.feed(data[i : i + 7])]
    assert whole == trickled
    assert len(whole) == len(synth.band_repair(order).chunks)


def test_reader_rejects_garbage():
    with pytest.raises(ie.TraceError):
        ie.PklgReader().feed(b"\x00\x00\x00\x01" * 8)


def test_reads_pklg_inside_a_sysdiagnose_tarball(tmp_path):
    data = synth.band_repair("<").data()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("sysdiagnose_x/logs/Bluetooth/bluetoothd-hci-latest.pklg")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    path = tmp_path / "sysdiagnose.tar.gz"
    path.write_bytes(buf.getvalue())
    assert list(ie.read_traces(path)) == [("sysdiagnose_x/logs/Bluetooth/bluetoothd-hci-latest.pklg", data)]


def test_full_repair_yields_both_irks_in_home_assistant_order():
    tracker, events = track(synth.band_repair())
    (band,) = tracker.paired_peers()
    assert tracker.is_target(band)
    assert band.peer == synth.BAND_RPA
    assert band.name_source == "GATT Device Name"
    assert band.peer_irk == synth.BAND_IRK
    assert band.peer_identity == f"{synth.BAND_IDENTITY} (random static)"
    assert band.phone_irk == synth.PHONE_IRK
    assert band.phone_identity == f"{synth.PHONE_IDENTITY} (public)"
    assert ie.pairing_method(band.request, band.response) == "LE Secure Connections, Just Works"
    assert band.peer_keys() == ie.KEY_ENC | ie.KEY_ID
    assert [e.kind for e in events].count(ie.Ev.IRK) == 2


def test_cancelled_background_connects_are_counted_not_narrated():
    tracker, events = track(synth.band_repair())
    assert tracker.cancelled_connects == 3
    assert all(e.addr != "00:00:00:00:00:00" for e in events)
    assert {e.conn.peer for e in events if e.kind is ie.Ev.CONNECTED} == {synth.OLD_BOND, synth.BAND_RPA}


@pytest.mark.parametrize(
    ("via", "source"),
    [
        ("apple", "Apple scan report"),
        ("adv", "advertising data"),
        ("discovery", "GATT Device Name"),
    ],
)
def test_name_matching_paths(via, source):
    tracker, _ = track(synth.band_repair(name_via=via))
    (band,) = tracker.paired_peers()
    assert band.name == synth.BAND_NAME
    assert band.name_source == source


def test_apple_scan_report_recovers_the_full_name_from_a_partial_target():
    tracker, _ = track(synth.band_repair(name_via="apple"), target="band")
    (band,) = tracker.paired_peers()
    assert band.name == synth.BAND_NAME
    assert tracker.is_target(band)


def test_unnamed_pairing_is_not_claimed_as_the_target():
    tracker, _ = track(synth.band_repair(name_via="none"))
    (band,) = tracker.paired_peers()
    assert band.name is None
    assert not tracker.is_target(band)


def test_fragmented_smp_pdu_is_reassembled():
    tracker, _ = track(synth.band_repair(split_irk=True))
    assert tracker.paired_peers()[0].peer_irk == synth.BAND_IRK


def test_handle_reuse_starts_a_new_connection():
    trace = synth.band_repair().connect(0x41, synth.OTHER_RPA).gatt_name(0x41, "Someone Else")
    tracker, _ = track(trace)
    band, other = [c for c in tracker.conns if c.handle == 0x41]
    assert band.name == synth.BAND_NAME and band.ended is not None
    assert other.name == "Someone Else" and other.ended is None


def test_session_stops_shortly_after_the_target_irk():
    trace = synth.band_repair()
    tracker = ie.Tracker(synth.BAND_NAME)
    session = ie.Session(tracker)
    stopped_at = None
    for rec in ie.PklgReader().feed(trace.data()):
        session.update(tracker.feed(rec), rec.ts)
        if session.done(rec.ts):
            stopped_at = rec.ts
            break
    assert stopped_at is not None
    assert tracker.paired_peers()[0].phone_irk == synth.PHONE_IRK


def test_session_gives_up_when_the_device_has_no_idkey():
    tracker = ie.Tracker(synth.BAND_NAME)
    session = ie.Session(tracker)
    for rec in ie.PklgReader().feed(synth.band_repair(responder_keys=ie.KEY_ENC).data()):
        session.update(tracker.feed(rec), rec.ts)
        if session.done(rec.ts):
            break
    assert session.no_irk is not None and session.no_irk.peer == synth.BAND_RPA
    assert tracker.paired_peers() == []


def test_pairing_method_table():
    def pdu(io_cap, auth):
        return bytes([0x01, io_cap, 0, auth, 16, 0, 0])

    assert ie.pairing_method(pdu(4, 0x2D), pdu(3, 0x0D)) == "LE Secure Connections, Just Works"
    assert ie.pairing_method(pdu(1, 0x0D), pdu(1, 0x0D)) == "LE Secure Connections, Numeric Comparison"
    assert ie.pairing_method(pdu(1, 0x05), pdu(1, 0x05)) == "LE Legacy Pairing, Just Works"
    assert ie.pairing_method(pdu(4, 0x0D), pdu(0, 0x0D)) == "LE Secure Connections, Passkey Entry"
    assert ie.pairing_method(pdu(4, 0x09), pdu(4, 0x09)) == "LE Secure Connections, Just Works"
