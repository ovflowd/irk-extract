"""Regression check against a real capture, which must never be committed.

IRK_EXTRACT_REAL_TRACE=local/capture.pklg IRK_EXTRACT_REAL_NAME="Google Fitbit Air" uv run pytest
"""

import os
from pathlib import Path

import pytest

import irk_extract as ie

TRACE = os.environ.get("IRK_EXTRACT_REAL_TRACE")
NAME = os.environ.get("IRK_EXTRACT_REAL_NAME")


@pytest.mark.skipif(not (TRACE and NAME), reason="no real capture configured")
def test_real_capture_yields_one_matching_irk_that_resolves_its_pairing_address():
    tracker = ie.Tracker(NAME)
    session = ie.Session(tracker)
    for _, data in ie.read_traces(Path(TRACE)):
        for rec in ie.PklgReader().feed(data):
            session.update(tracker.feed(rec), rec.ts)
            if session.done(rec.ts):
                break
    matched = [c for c in tracker.paired_peers() if tracker.is_target(c)]
    assert len(matched) == 1
    (conn,) = matched
    assert conn.peer_identity and conn.phone_irk
    assert any(ie.resolves(conn.peer_irk, a) for a in conn.addresses())
