"""The Scan capability: shared content analysis that defenses call through
`context.scan`.

Scan finds evidence; it never decides. Each method takes a string or any
JSON value (mappings and sequences are walked at any depth) and returns
neutral matches that point at where the evidence is. The defense turns
matches into findings under its own rule ids, and policy decides what they
mean.

A match never carries the inspected text, only a JSON Pointer and a
character range, so evidence can be logged without leaking content.

Scan is async and stage-aware so later stages (a local classifier, a model
check) can sit behind the same methods without changing defenses. A scan
that cannot complete raises `ScanError`; it never returns an empty result
for content it did not inspect.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class ScanError(RuntimeError):
    """A scan could not complete, so its content is unknown, never clean."""


class ScanLimitError(ScanError):
    """The value was too large to scan within the time a defense has."""


class Detector(StrEnum):
    """The scan methods, one per kind of evidence."""

    HIDDEN = "hidden"
    INSTRUCTIONS = "instructions"
    LOOKALIKES = "lookalikes"
    SECRETS = "secrets"
    COMMANDS = "commands"


class MatchKind(StrEnum):
    # hidden: content a person reading the text would not see
    HTML_COMMENT = "html_comment"
    MARKDOWN_COMMENT = "markdown_comment"
    INVISIBLE_CHARACTER = "invisible_character"
    BIDI_CONTROL = "bidi_control"
    TAG_CHARACTER = "tag_character"
    CONTROL_CHARACTER = "control_character"
    DATA_URI = "data_uri"
    ENCODED_TEXT = "encoded_text"
    PADDING = "padding"
    # instructions: text addressed to the model rather than the reader
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_SWITCH = "role_switch"
    CHAT_TEMPLATE_TOKEN = "chat_template_token"
    FAKE_AUTHORITY = "fake_authority"
    # lookalikes
    MIXED_SCRIPT_CONFUSABLE = "mixed_script_confusable"
    # secrets; `ScanMatch.label` names the format
    SECRET = "secret"
    # commands (SDK 1.2): values a model would run, or files it would read
    SHELL_COMMAND = "shell_command"
    CREDENTIAL_PATH = "credential_path"


class Decoding(StrEnum):
    """A transformation that had to be undone to reveal a match."""

    NORMALIZATION = "normalization"  # NFKC, invisible characters removed
    CONFUSABLES = "confusables"  # lookalike letters mapped to their prototype
    UNICODE_TAGS = "unicode_tags"
    BASE64 = "base64"
    BASE64_URL = "base64_url"
    PERCENT = "percent"


class ScanStage(StrEnum):
    """The stage that produced a match. Only `rules` exists today."""

    RULES = "rules"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ScanMatch:
    """One piece of evidence.

    `pointer` is a JSON Pointer into the scanned value (`""` when the value
    is a string). `span` is a character range in the string at `pointer`;
    for a match revealed by decoding it covers the whole encoded segment.
    When `in_key` is set, the match is in the mapping key at `pointer`
    rather than its value.

    `concealed` means the match was revealed only by decoding, or sits
    inside hidden content: evidence of intent, since benign text has no
    reason to hide.
    """

    detector: Detector
    kind: MatchKind
    pointer: str
    span: tuple[int, int]
    confidence: Confidence
    decoded_by: tuple[Decoding, ...] = ()
    concealed: bool = False
    in_key: bool = False
    stage: ScanStage = ScanStage.RULES
    label: str = ""

    @property
    def ref(self) -> str:
        """An evidence reference such as `/description#12-40`."""
        start, end = self.span
        location = f"{self.pointer}#key" if self.in_key else self.pointer
        return f"{location}#{start}-{end}"


@dataclass(frozen=True)
class ScanResult:
    """`version` identifies the scanner and its data, for audit records."""

    matches: tuple[ScanMatch, ...]
    version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "matches", tuple(self.matches))


class ScanView(Protocol):
    """Every method accepts a string or a JSON value and may raise `ScanError`."""

    async def hidden(self, value: Any) -> ScanResult: ...

    async def instructions(self, value: Any) -> ScanResult: ...

    async def lookalikes(self, value: Any) -> ScanResult: ...

    async def secrets(self, value: Any) -> ScanResult: ...

    async def skeleton(self, text: str) -> str:
        """The UTS #39 confusable skeleton of `text` (SDK 1.2).

        Two strings that look alike, such as `send_message` and `send_mеssage`
        with a Cyrillic "е", have the same skeleton. Compare skeletons rather
        than mapping lookalike letters in a defense.
        """
        ...

    async def skeletons(self, texts: Iterable[str]) -> Mapping[str, str]:
        """`skeleton` for many strings in one call, keyed by text (SDK 1.2).

        Comparing one name against every exposed tool needs the skeleton of
        each; one call keeps that linear in the number of names.
        """
        ...

    async def commands(self, value: Any) -> ScanResult:
        """Shell command syntax and credential file paths (SDK 1.2)."""
        ...
