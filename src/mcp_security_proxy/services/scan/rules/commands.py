"""Values a model would run on the user's machine, or credential files it would read.

Tool poisoning through schema values (a `default` or `examples` entry the
model copies into a call) needs no hidden text: the value is simply a
command or the path of a secret. Written from public descriptions of such
attacks, two kinds of evidence:

- **shell commands**: piping into an interpreter (`| sh`), downloading with
  `curl` or `wget`, command substitution (`$(...)`), chaining into a
  network or shell command (`; curl`, `&& bash`), inline interpreter code
  (`python -c`, `bash -c`, `powershell -enc`), and recursive deletion of a
  root or home path;
- **credential paths**: private SSH keys, cloud and package-registry
  credentials, `.env` and `.netrc` files, `/etc/shadow`.

Backticks and bare semicolons are not evidence: Markdown and CSS use them.
Public files under `~/.ssh` (`config`, `known_hosts`, `*.pub`) are not
credentials. Every view is searched, so encoding can't hide either kind.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_security_proxy.sdk import Confidence, Detector, MatchKind
from mcp_security_proxy.services.scan.rules.base import Evidence, search
from mcp_security_proxy.services.scan.views import TextViews

_COMMAND_WORD = (
    r"(?:curl|wget|nc|ncat|netcat|bash|sh|zsh|powershell|pwsh|iex|scp|ssh|chmod|rm|eval"
    r"|python3?|node|perl)"
)
_SHELL = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|perl|iex|invoke-expression)\b"
    r"|\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]{0,200}?\bhttps?://"
    r"|\$\([^)\n]{1,200}\)"
    rf"|(?:;|&&|\|\|)\s*{_COMMAND_WORD}\b"
    r"|\b(?:python3?|node|perl|ruby)\s+-[ce]\s"
    r"|\b(?:bash|sh|zsh)\s+-c\s"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\s+(?:-enc\w*|-e|-command|-c)\s"
    r"|\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+(?:/|~|\$HOME)",
    re.I,
)
_CREDENTIAL_PATH = re.compile(
    r"(?<![\w.-])"
    r"(?:(?:~|\$HOME|%USERPROFILE%)?[/\\])?"
    r"(?:\.ssh[/\\]id_(?:rsa|dsa|ecdsa|ed25519)(?![\w.])"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)(?![\w.])"
    r"|\.aws[/\\]credentials\b|\.azure[/\\]accessTokens\.json\b"
    r"|\.config[/\\]gcloud[/\\](?:credentials\.db|application_default_credentials\.json)\b"
    r"|\.config[/\\]gh[/\\]hosts\.yml\b|\.kube[/\\]config\b|\.docker[/\\]config\.json\b"
    r"|\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b|\.env(?![\w.-])"
    r"|\.gnupg[/\\]|/etc/(?:shadow|sudoers)\b)",
    re.I,
)


class CommandsRule:
    detector = Detector.COMMANDS

    def detect(self, text: TextViews) -> Iterator[Evidence]:
        for view in text.views():
            yield from search(_SHELL, view, MatchKind.SHELL_COMMAND, Confidence.MEDIUM)
            yield from search(_CREDENTIAL_PATH, view, MatchKind.CREDENTIAL_PATH, Confidence.HIGH)
