"""Check launched servers against a pinned SHA-256 before starting them (plan MR E1).

An operator who vetted a server binary or script pins it with `sha256` in
the server's config entry. At startup the proxy resolves `command` to a
file (an absolute or relative path, or the first match on `PATH`), hashes
it, and refuses to start if the hash differs or the file can't be found:
a pin means "only this", so a mismatch is never left to policy. The proxy
then launches the exact file it hashed, so a different file earlier on
`PATH` can't be swapped in between the check and the launch.

The pin covers the file `command` names, nothing it loads. For an
interpreter (`python -m server`) or a package runner (`npx some-server`) it
pins only the interpreter or the runner; pin the package version instead
(see the server admission runbook).

The result per server is `verified` or `unpinned`, kept for the server
identity view (ADR 0022), which will expose it to defenses as `integrity`.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from mcp_security_proxy.app.config import ConfigError, UpstreamServerConfig

_CHUNK = 1024 * 1024


class ServerIntegrityError(ConfigError):
    """A pinned server's file is missing or its SHA-256 differs from the pin."""


class Integrity(StrEnum):
    VERIFIED = "verified"
    UNPINNED = "unpinned"


@dataclass(frozen=True)
class ServerIntegrity:
    server_id: str
    status: Integrity
    # The file to launch: the one that was hashed when verified.
    command: str


def resolve_command(command: str) -> Path | None:
    """The file `command` launches: a path as given, or the first match on PATH."""
    if Path(command).name != command:
        path = Path(command)
        return path.resolve() if path.is_file() else None
    found = shutil.which(command)
    return Path(found).resolve() if found else None


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def check_server(upstream: UpstreamServerConfig) -> ServerIntegrity:
    if upstream.sha256 is None:
        return ServerIntegrity(upstream.id, Integrity.UNPINNED, upstream.command)
    path = resolve_command(upstream.command)
    if path is None:
        raise ServerIntegrityError(
            f"server {upstream.id!r}: pinned command {upstream.command!r} was not found; "
            "refusing to start it"
        )
    try:
        actual = file_sha256(path)
    except OSError as exc:
        raise ServerIntegrityError(
            f"server {upstream.id!r}: cannot read {path} to check its pin: {exc}"
        ) from exc
    if actual != upstream.sha256:
        raise ServerIntegrityError(
            f"server {upstream.id!r}: {path} has SHA-256 {actual}, but the config pins "
            f"{upstream.sha256}; refusing to start it"
        )
    return ServerIntegrity(upstream.id, Integrity.VERIFIED, str(path))


def check_servers(upstreams: Iterable[UpstreamServerConfig]) -> Mapping[str, ServerIntegrity]:
    """Every server's integrity, or `ServerIntegrityError` for the first bad pin."""
    return {upstream.id: check_server(upstream) for upstream in upstreams}
