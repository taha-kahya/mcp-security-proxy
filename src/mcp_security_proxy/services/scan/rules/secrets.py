"""Credentials in well-known formats, found in plain and decoded text.

Only formats with a distinctive prefix or structure are matched, so random
identifiers don't look like keys. No entropy guessing: it flags hashes,
UUIDs and ids far more often than secrets. `label` names the format.
Lookalike-folded views are skipped, since a key spelled with lookalike
letters is not a working key.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_security_proxy.sdk import Confidence, Detector, MatchKind
from mcp_security_proxy.services.scan.rules.base import Evidence
from mcp_security_proxy.services.scan.views import TextViews

_FORMATS: tuple[tuple[str, re.Pattern[str], Confidence], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Confidence.HIGH),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), Confidence.HIGH),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), Confidence.HIGH),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), Confidence.HIGH),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), Confidence.HIGH),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), Confidence.HIGH),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Confidence.HIGH),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), Confidence.HIGH),
    (
        "openai_api_key",
        re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
        Confidence.MEDIUM,
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
        Confidence.HIGH,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        Confidence.MEDIUM,
    ),
)


# All formats in one pattern, one named group each, so text is scanned once.
_ANY_FORMAT = re.compile(
    "|".join(f"(?P<f{index}>{pattern.pattern})" for index, (_, pattern, _) in enumerate(_FORMATS))
)


class SecretsRule:
    detector = Detector.SECRETS

    def detect(self, text: TextViews) -> Iterator[Evidence]:
        for view in text.views():
            if view.is_folded:
                continue
            for match in _ANY_FORMAT.finditer(view.text):
                label, _, confidence = _FORMATS[int(str(match.lastgroup)[1:])]
                yield Evidence(MatchKind.SECRET, view.locate(*match.span()), confidence, label)
