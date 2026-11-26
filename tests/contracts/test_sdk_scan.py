"""The Scan contract as defenses see it: capability grants, match references,
and the scripted `FakeScan` used in defense tests."""

from __future__ import annotations

import pytest

from mcp_security_proxy.sdk import (
    Capability,
    CapabilityNotGrantedError,
    Confidence,
    Decoding,
    Detector,
    Manifest,
    MatchKind,
    ScanMatch,
    Stage,
)
from mcp_security_proxy.sdk.testing import FakeScan, make_context

MATCH = ScanMatch(
    Detector.HIDDEN, MatchKind.HTML_COMMENT, "/description", (4, 30), Confidence.MEDIUM
)


def _manifest(*capabilities: Capability) -> Manifest:
    return Manifest(
        id="sample",
        version="1.0.0",
        sdk_version_range=">=1.1,<2",
        stages=frozenset({Stage.DISCOVERY}),
        required_capabilities=frozenset(capabilities),
    )


def test_scan_is_granted_only_when_declared() -> None:
    with pytest.raises(CapabilityNotGrantedError):
        _ = make_context(_manifest()).scan
    assert make_context(_manifest(Capability.SCAN)).scan is not None


def test_make_context_refuses_an_undeclared_scan() -> None:
    with pytest.raises(ValueError, match="scan"):
        make_context(_manifest(), scan=FakeScan())


@pytest.mark.parametrize(
    ("match", "ref"),
    [
        pytest.param(MATCH, "/description#4-30", id="value"),
        pytest.param(
            ScanMatch(
                Detector.HIDDEN,
                MatchKind.INVISIBLE_CHARACTER,
                "/inputSchema/properties/path",
                (0, 1),
                Confidence.MEDIUM,
                in_key=True,
            ),
            "/inputSchema/properties/path#key#0-1",
            id="key",
        ),
    ],
)
def test_match_ref_names_a_location_never_content(match: ScanMatch, ref: str) -> None:
    assert match.ref == ref


def test_matches_default_to_the_rules_stage_and_no_decoding() -> None:
    assert MATCH.stage == "rules"
    assert MATCH.decoded_by == () and not MATCH.concealed


async def test_fake_scan_filters_by_detector_and_records_calls() -> None:
    secret = ScanMatch(
        Detector.SECRETS,
        MatchKind.SECRET,
        "",
        (0, 20),
        Confidence.HIGH,
        decoded_by=(Decoding.BASE64,),
        label="aws_access_key_id",
    )
    scan = FakeScan(matches=(MATCH, secret))

    assert (await scan.hidden({"description": "x"})).matches == (MATCH,)
    assert (await scan.secrets("y")).matches == (secret,)
    assert (await scan.lookalikes("z")).matches == ()
    assert [d for d, _ in scan.scanned] == [Detector.HIDDEN, Detector.SECRETS, Detector.LOOKALIKES]
