"""The vendored Unicode data: pinned files, and the lookups built on them."""

from __future__ import annotations

import hashlib
from importlib.resources import files

import pytest

from mcp_security_proxy.services.scan.unicode_data import (
    UNICODE_VERSION,
    parse_scripts,
    unicode_data,
)

PINNED_SHA256 = {
    "confusables.txt": "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
    "Scripts.txt": "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
    "LICENSE.txt": "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96",
}


@pytest.mark.parametrize(("name", "digest"), PINNED_SHA256.items())
def test_vendored_files_match_their_pinned_hashes(name: str, digest: str) -> None:
    folder = files("mcp_security_proxy.services.scan").joinpath(
        "data", f"unicode-{UNICODE_VERSION}"
    )
    assert hashlib.sha256(folder.joinpath(name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize(
    ("char", "script"),
    [
        ("a", "Latin"),
        ("а", "Cyrillic"),  # CYRILLIC SMALL LETTER A
        ("μ", "Greek"),
        ("東", "Han"),
        ("7", "Common"),
        ("́", "Inherited"),  # COMBINING ACUTE ACCENT
        ("\U0010ffff", "Unknown"),
    ],
)
def test_script_lookup(char: str, script: str) -> None:
    assert unicode_data().script(char) == script


def test_cyrillic_lookalike_maps_to_its_latin_prototype() -> None:
    assert unicode_data().prototype("а") == "a"
    assert unicode_data().prototype("a") == "a"


@pytest.mark.parametrize(
    ("first", "second", "alike"),
    [
        ("read_file", "reаd_file", True),
        ("paypal", "pаypаl", True),
        ("read_file", "read_files", False),
    ],
)
def test_skeletons_are_equal_only_for_lookalikes(first: str, second: str, alike: bool) -> None:
    data = unicode_data()
    assert (data.skeleton(first) == data.skeleton(second)) is alike


def test_script_ranges_parse_single_points_and_ranges() -> None:
    ranges = parse_scripts("0041..005A ; Latin # A..Z\n00AA ; Latin # ordinal\n")
    assert ranges.script("B") == "Latin"
    assert ranges.script("ª") == "Latin"
    assert ranges.script("«") == "Unknown"
