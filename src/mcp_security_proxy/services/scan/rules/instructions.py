"""Instructions addressed to the model rather than to the reader.

A deliberately narrow list, written from public descriptions of prompt
injection, of patterns that rarely occur by accident:

- **instruction overrides**: an override verb aimed at the model's
  instructions, with a word that scopes it ("ignore all previous
  instructions"), but not "ignore the instructions in the README";
- **role switches**: "you are now in developer mode", "you are now the system
  administrator", "act as the root user", "new instructions:";
- **chat-template tokens**: `<|im_start|>`, `[INST]`, `<<SYS>>`;
- **fake authority markers**: `<system>`, `<important>`, `[SYSTEM]`.

Words may be separated by spaces, `_` or `-`, so a parameter named
`ignore_previous_instructions` matches too (camelCase isn't split).

Overrides and role switches directly preceded by a negation ("never ignore
your instructions", "do not ever ...") are not matched, as in SkillSpector's
prohibition context. Only a few adverbs may stand between the negation and
the verb, so a leading "never mind" or "without delay" does not count.
Every view is searched, so encoding and lookalike letters can't hide a
phrase.

What this does not catch: reworded injections ("kindly set aside what you
were told"). That needs a classifier stage behind the same method.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_security_proxy.sdk import Confidence, Detector, MatchKind
from mcp_security_proxy.services.scan.rules.base import Evidence, search
from mcp_security_proxy.services.scan.views import TextViews, View

_VERB = (
    r"(?:ignor(?:e|ing)|disregard(?:ing)?|forget(?:ting)?|overrid(?:e|ing)"
    r"|bypass(?:ing)?|skip(?:ping)?)"
)
_FILLER = (
    r"(?:all|any|every|the|your|my|of|these|those|previous|prior|preceding|above|earlier"
    r"|former|original|initial|system|safety|developer|existing|current)"
)
_TARGET = (
    r"(?:instructions?|rules|directives?|guidelines|prompts?|guardrails|polic(?:y|ies)"
    r"|constraints)"
)
# Words that aim the override at instructions the model already has.
_SCOPE = frozenset(
    "all any every your previous prior preceding above earlier former original initial "
    "system safety developer existing current".split()
)
# Spaces, or the `_` and `-` that join words in identifiers such as parameter names.
_SEP = r"[\s_\-]+"
_START = r"(?<![A-Za-z0-9])"
_END = r"(?![A-Za-z0-9])"
_OVERRIDE = re.compile(
    rf"{_START}{_VERB}(?P<filler>(?:{_SEP}{_FILLER}){{1,4}}){_SEP}{_TARGET}{_END}", re.I
)
# Roles that carry authority over the model or the system.
_ROLE = (
    r"(?:system|administrator|admin|root|superuser|sudo|developer|operator|unrestricted"
    r"|unfiltered|jailbroken)"
)
_ROLE_SWITCH = re.compile(
    r"\byou\s+are\s+now\s+(?:no\s+longer\b|in\s+\w+\s+mode\b)"
    rf"|\byou\s+are\s+now\s+(?:an?\s+|the\s+)?(?:\w+\s+)?{_ROLE}\b"
    rf"|(?:^|[.!?:]\s*)act\s+as\s+(?:an?\s+|the\s+)?(?:\w+\s+)?{_ROLE}\b"
    r"|\bfrom\s+now\s+on,?\s+you\s+(?:must|shall|are\s+to|will\s+(?:only|always|never))\b"
    r"|\b(?:new|updated|real|actual|revised)\s+(?:system\s+)?(?:instructions|prompt)\s*:",
    re.I,
)
_CHAT_TEMPLATE = re.compile(
    r"<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|begin_of_text"
    r"|start_header_id|end_header_id)\|>"
    r"|\[/?INST\]|<</?SYS>>|<(?:start|end)_of_turn>"
)
# Tags in any case; bracketed labels only in capitals, so "[system]" in prose stays clean.
_AUTHORITY_TAG = re.compile(
    r"</?(?:system|system_prompt|instructions|important|admin|developer)>", re.I
)
_AUTHORITY_LABEL = re.compile(
    r"\[(?:SYSTEM|ADMIN|DEVELOPER)(?:\s+(?:MESSAGE|NOTE|OVERRIDE|PROMPT))?\]"
)
_NEGATED = re.compile(
    r"(?:\b(?:never|not|avoid|refuse\s+to|without)|n't)\s+(?:(?:ever|just|simply|to)\s+)?$",
    re.I,
)


class InstructionsRule:
    detector = Detector.INSTRUCTIONS

    def detect(self, text: TextViews) -> Iterator[Evidence]:
        for view in text.views():
            yield from _overrides(view)
            yield from _unless_negated(view, _ROLE_SWITCH, MatchKind.ROLE_SWITCH, Confidence.LOW)
            yield from search(_CHAT_TEMPLATE, view, MatchKind.CHAT_TEMPLATE_TOKEN, Confidence.HIGH)
            for pattern in (_AUTHORITY_TAG, _AUTHORITY_LABEL):
                yield from search(pattern, view, MatchKind.FAKE_AUTHORITY, Confidence.MEDIUM)


def _overrides(view: View) -> Iterator[Evidence]:
    for match in _OVERRIDE.finditer(view.text):
        scoped = _SCOPE & set(re.split(_SEP, match.group("filler").lower()))
        if scoped and not _negated(view.text, match.start()):
            located = view.locate(*match.span())
            yield Evidence(MatchKind.INSTRUCTION_OVERRIDE, located, Confidence.MEDIUM)


def _unless_negated(
    view: View, pattern: re.Pattern[str], kind: MatchKind, confidence: Confidence
) -> Iterator[Evidence]:
    for match in pattern.finditer(view.text):
        if not _negated(view.text, match.start()):
            yield Evidence(kind, view.locate(*match.span()), confidence)


def _negated(text: str, start: int) -> bool:
    return _NEGATED.search(text[max(start - 40, 0) : start]) is not None
