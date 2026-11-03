import base64
import io
import os
import sys
from pathlib import Path

import pytest

import irk_extract as ie
import synth

HERE = Path(__file__).parent


@pytest.fixture(autouse=True)
def wide_console(monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")


def replay(tmp_path, trace, *args):
    path = tmp_path / "trace.pklg"
    path.write_bytes(trace.data())
    return ie.main(["--replay", str(path), *args])


def test_replay_prints_the_irk_in_both_home_assistant_forms(tmp_path, capsys):
    assert replay(tmp_path, synth.band_repair(), "--name", synth.BAND_NAME) == 0
    out = capsys.readouterr().out
    assert synth.BAND_IRK.hex() in out
    assert base64.b64encode(bytes(reversed(synth.BAND_IRK))).decode() in out
    assert synth.PHONE_IRK.hex() in out
    assert f"resolves {synth.BAND_RPA}" in out
    assert "Private BLE Device" in out
    assert "00:00:00:00:00:00" not in out


def test_replay_narrates_the_pairing(tmp_path, capsys):
    replay(tmp_path, synth.band_repair(name_via="apple"), "--name", synth.BAND_NAME)
    out = capsys.readouterr().out
    assert "Capturing from iPhone99,1, iOS 99.0, Test Chip" in out
    assert f"Connected to {synth.BAND_NAME}" in out
    assert "Pairing Response" in out and "LE Secure Connections, Just Works" in out
    assert f"{synth.BAND_NAME} will send EncKey+IdKey, the iPhone IdKey" in out
    assert f"{synth.BAND_NAME} sent its IRK" in out
    assert "hid 3 cancelled background connects" in out


def test_replay_warns_when_the_device_withholds_its_irk(tmp_path, capsys):
    assert replay(tmp_path, synth.band_repair(responder_keys=ie.KEY_ENC), "--name", synth.BAND_NAME) == 1
    out = capsys.readouterr().out
    assert "will never send an IRK" in out
    assert "No IRK to extract" in out


def test_replay_explains_pairing_failures(tmp_path, capsys):
    trace = synth.Trace().connect(0x42, synth.BAND_RPA).gatt_name(0x42, synth.BAND_NAME)
    trace.pairing(0x42, synth.BAND_IRK, synth.BAND_IDENTITY, fail=0x09)
    assert replay(tmp_path, trace, "--name", synth.BAND_NAME) == 1
    out = capsys.readouterr().out
    assert "Pairing failed: Repeated Attempts (reported by Test Band)" in out
    assert "Wait a minute" in out


def test_replay_hints_at_an_existing_bond(tmp_path, capsys):
    trace = synth.Trace().connect(0x40, synth.BAND_RPA).gatt_name(0x40, synth.BAND_NAME).encrypted(0x40)
    assert replay(tmp_path, trace, "--name", synth.BAND_NAME) == 1
    assert "still remembers" in capsys.readouterr().out


def test_replay_without_a_name_lists_every_device_that_paired(tmp_path, capsys):
    trace = synth.band_repair(name_via="none").connect(0x42, synth.OTHER_RPA)
    trace.pairing(0x42, synth.OTHER_IRK, "C1:00:00:00:00:02").idle()
    assert replay(tmp_path, trace) == 0
    out = capsys.readouterr().out
    assert "Devices that sent an IRK" in out
    assert synth.BAND_IRK.hex() in out and synth.OTHER_IRK.hex() in out


def test_replay_of_a_missing_file_fails_cleanly(tmp_path, capsys):
    assert ie.main(["--replay", str(tmp_path / "nope.pklg")]) == 2
    assert "No such file" in capsys.readouterr().out


def test_pmd3_command_can_be_overridden(monkeypatch):
    monkeypatch.setenv("IRK_EXTRACT_PMD3", "/opt/pmd3 --verbose")
    assert ie.pmd3_command() == ["/opt/pmd3", "--verbose"]


def test_missing_usbmuxd_prints_the_install_command_and_never_runs_sudo(monkeypatch, capsys):
    monkeypatch.setattr(ie, "usbmuxd_problem", lambda: "missing")
    monkeypatch.setattr(ie, "install_hint", lambda: "sudo pacman -S --needed usbmuxd")
    monkeypatch.setattr(ie.subprocess, "run", lambda *a, **k: pytest.fail("ran a command"))
    monkeypatch.setattr(ie.subprocess, "Popen", lambda *a, **k: pytest.fail("ran a command"))
    assert ie.main(["--name", synth.BAND_NAME]) == 2
    out = capsys.readouterr().out
    assert "sudo pacman -S --needed usbmuxd" in out


def test_guided_flow_end_to_end_with_a_fake_iphone(tmp_path, monkeypatch, capsys):
    profile = tmp_path / "iOSBluetoothLogging.mobileconfig"
    profile.write_bytes(b"<plist>com.apple.bluetooth.logging</plist>")
    out = tmp_path / "capture.pklg"
    monkeypatch.setenv("IRK_EXTRACT_PMD3", f"{sys.executable} {HERE / 'fake_pmd3.py'}")
    monkeypatch.setenv("FAKE_PMD3_STATE", str(tmp_path))
    monkeypatch.setattr(ie, "usbmuxd_problem", lambda: None)
    monkeypatch.setattr(ie.Session, "GRACE_FOUND", 0.3)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{profile}\ny\n"))

    assert ie.main(["--name", synth.BAND_NAME, "--out", str(out)]) == 0

    text = capsys.readouterr().out
    assert "Found Test iPhone (iPhone99,1, iOS 99.0)" in text
    assert "Profile Downloaded" in text
    assert "Bluetooth logging profile installed" in text
    assert "Bluetooth traffic is flowing" in text
    assert "Forget This Device" in text
    assert synth.BAND_IRK.hex() in text
    assert "Profile removed" in text
    calls = (tmp_path / "calls.log").read_text().splitlines()
    assert f"profile install {profile}" in calls
    assert f"profile remove {ie.PROFILE_ID}" in calls
    assert f"btlogger {out}" in calls
    assert out.read_bytes() == synth.band_repair(name_via="apple").data()
    assert os.stat(out).st_mode & 0o077 == 0
    assert not (tmp_path / "installed").exists()
