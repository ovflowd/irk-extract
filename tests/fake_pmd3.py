"""Stands in for the pymobiledevice3 CLI in the live-flow test (via IRK_EXTRACT_PMD3)."""

import json
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import irk_extract as ie
import synth

state = Path(os.environ["FAKE_PMD3_STATE"])
args = [a for a in sys.argv[1:] if a != "--no-color"]
if "--udid" in args:
    i = args.index("--udid")
    del args[i : i + 2]
with open(state / "calls.log", "a") as log:
    log.write(" ".join(args) + "\n")

installed, pending = state / "installed", state / "pending"
command = args[:2]

if command == ["usbmux", "list"]:
    device = {
        "ConnectionType": "USB",
        "DeviceName": "Test iPhone",
        "Identifier": "0000-TEST",
        "ProductType": "iPhone99,1",
        "ProductVersion": "99.0",
        "UniqueDeviceID": "0000-TEST",
    }
    print(json.dumps([device]))
elif command == ["lockdown", "device-name"]:
    print("Test iPhone")
elif command == ["profile", "list"]:
    if pending.exists():
        pending.rename(installed)
        print(json.dumps({"ProfileMetadata": {}}))
    elif installed.exists():
        meta = {"PayloadDisplayName": "Bluetooth Logging for iOS", "PayloadUUID": "X", "PayloadVersion": 1}
        print(json.dumps({"ProfileMetadata": {ie.PROFILE_ID: meta}}))
    else:
        print(json.dumps({"ProfileMetadata": {}}))
elif command == ["profile", "install"]:
    pending.touch()
elif command == ["profile", "remove"]:
    installed.unlink(missing_ok=True)
elif args[0] == "btlogger":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    trace = synth.band_repair(name_via="apple")
    with open(args[1], "wb") as out:
        for chunk in trace.chunks:
            out.write(chunk)
            out.flush()
            time.sleep(0.005)
    while True:
        time.sleep(1)
else:
    print(f"fake pymobiledevice3: unexpected {args}", file=sys.stderr)
    sys.exit(1)
