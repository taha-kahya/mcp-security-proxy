"""Where a URL or host points, judged from its text alone.

`classify_destination` labels a destination as cloud metadata, loopback,
link-local, private, reserved, external, an unresolved name, or invalid. It
does no DNS lookup or other I/O, so a defense can call it inside its
deadline, and it never raises on bad input.

Hosts are parsed with the WHATWG URL rules that browsers follow, so a
disguised address gets the same label as the plain one. Python's clients
don't all follow WHATWG: where a URL can be read two ways, both hosts are
classified and the more sensitive label wins (see `ambiguous_authority`).
Each of these is `metadata`:

    http://169.254.169.254/        http://2852039166/
    http://0xA9FEA9FE/             http://0251.0376.0251.0376/
    http://169.254.43518/          http://169%2e254%2e169%2e254/
    http://user@169.254.169.254/   http://[::ffff:169.254.169.254]/
    http://169.254.169.254.nip.io/ http:\\\\169.254.169.254
    http://evil.com\\@169.254.169.254/

What text can't tell: where a hostname resolves. `api.example.com` is
labeled `name`, never `external`, because a name an attacker controls can
resolve to an internal address (DNS rebinding), and an external address
can redirect to an internal one. Network egress policy is the only control
for either; this classifier is a check on top of it.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, replace
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from urllib.parse import unquote

IPAddress = IPv4Address | IPv6Address


class DestinationKind(StrEnum):
    METADATA = "metadata"  # cloud instance metadata, which hands out credentials
    LOOPBACK = "loopback"  # the machine the request is sent from
    LINK_LOCAL = "link_local"
    PRIVATE = "private"  # RFC 1918, unique local, carrier NAT, internal names
    RESERVED = "reserved"  # multicast, documentation, benchmarking, special-use names
    EXTERNAL = "external"  # a public IP address
    NAME = "name"  # a hostname that can't be placed without DNS
    INVALID = "invalid"  # no host, or one that doesn't parse


# Internal kinds, most sensitive first.
_INTERNAL_PRIORITY = (
    DestinationKind.METADATA,
    DestinationKind.LOOPBACK,
    DestinationKind.LINK_LOCAL,
    DestinationKind.PRIVATE,
)
INTERNAL_KINDS = frozenset(_INTERNAL_PRIORITY)


class HostForm(StrEnum):
    """How the host was written. Anything but `name` or `ip` is a disguise."""

    NONE = "none"  # no host: invalid input or a local `file:` URL
    NAME = "name"
    IP = "ip"  # an IP address in its usual form
    IP_OBFUSCATED = "ip_obfuscated"  # decimal, hex, octal, short, encoded, or IPv4 in IPv6
    IP_IN_NAME = "ip_in_name"  # an internal IP spelled inside a hostname


@dataclass(frozen=True)
class Destination:
    """The label for one destination, and what it was decided from.

    `host` is the normalized host (lowercase, decoded, without brackets).
    `address` is the IP address that decided the label: the parsed literal,
    the IPv4 address carried inside an IPv6 one, or the one spelled inside a
    name. `port` is set only when written explicitly. `reason` names the
    rule that decided, for findings and logs.
    """

    kind: DestinationKind
    form: HostForm
    reason: str
    host: str | None = None
    address: IPAddress | None = None
    scheme: str | None = None
    port: int | None = None

    @property
    def is_internal(self) -> bool:
        """Whether the destination is inside the deployment's network.

        False for `name` and `invalid` too: they are not known to be
        internal, and not known to be external either.
        """
        return self.kind in INTERNAL_KINDS


def classify_destination(value: str) -> Destination:
    """Label a URL (`https://host:443/path`), a host, or `host:port`."""
    try:
        target, *alternates = _parse(value)
    except _InvalidError as error:
        return Destination(DestinationKind.INVALID, HostForm.NONE, error.reason)
    destination = _destination(target)
    for alternate in alternates:
        other = _destination(alternate)
        if _more_sensitive(other, destination):
            return replace(other, reason="ambiguous_authority")
    return destination


def _more_sensitive(candidate: Destination, current: Destination) -> bool:
    if not candidate.is_internal:
        return False
    if not current.is_internal:
        return True
    return _INTERNAL_PRIORITY.index(candidate.kind) < _INTERNAL_PRIORITY.index(current.kind)


def _destination(target: _Target) -> Destination:
    if target.host is None:
        return Destination(
            DestinationKind.LOOPBACK, HostForm.NONE, "local_file", scheme=target.scheme
        )
    try:
        verdict = _classify_host(target.host)
    except _InvalidError as error:
        return Destination(
            DestinationKind.INVALID, HostForm.NONE, error.reason, scheme=target.scheme
        )
    return Destination(
        verdict.kind,
        _disguised(verdict.form) if target.encoded and verdict.address else verdict.form,
        verdict.reason,
        verdict.host,
        verdict.address,
        target.scheme,
        target.port,
    )


# --- Parsing -----------------------------------------------------------------

_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.IGNORECASE)
# `host:8080` or `host:` looks like a scheme but is a host and a port.
_PORT_ONLY = re.compile(r"(?:[0-9]+(?:[/?#\\]|$)|$)")
_AUTHORITY_END = re.compile(r"[/?#\\]")
_LENIENT_AUTHORITY_END = re.compile(r"[/?#]")
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
_STRIPPED = "".join(chr(code) for code in range(0x21))  # C0 controls and space
_REMOVED = str.maketrans("", "", "\t\n\r")
# Code points no client accepts in a host (WHATWG forbidden domain code points).
_FORBIDDEN_HOST = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")
_IDEOGRAPHIC_FULL_STOP = "。"
_MAX_HOST_LENGTH = 253


class _InvalidError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Target:
    scheme: str | None
    host: str | None  # None only for a `file:` URL without a host
    port: int | None
    encoded: bool  # percent-encoding or Unicode compatibility forms in the host


def _parse(value: str) -> list[_Target]:
    """The WHATWG reading first, then any other reading a client may make."""
    text = value.strip(_STRIPPED).translate(_REMOVED)
    if not text:
        raise _InvalidError("empty")
    if _bare_ipv6(text):
        return [_Target(None, *_host_and_port(f"[{text}]"))]
    scheme_match = _SCHEME.match(text)
    if scheme_match is None or _PORT_ONLY.match(text, scheme_match.end()):
        return _targets(None, text)
    scheme = scheme_match.group()[:-1].lower()
    rest = text[scheme_match.end() :]
    if scheme in _SPECIAL_SCHEMES:
        return _targets(scheme, rest.lstrip("/\\"))
    if not rest.startswith(("//", "\\\\", "/\\", "\\/")):
        if scheme == "file":
            return [_Target(scheme, None, None, False)]
        raise _InvalidError("no_host")
    if scheme == "file" and _authority(rest[2:]).lower() in ("", "localhost"):
        return [_Target(scheme, None, None, False)]
    return _targets(scheme, rest[2:])


def _targets(scheme: str | None, text: str) -> list[_Target]:
    """WHATWG ends the authority at a backslash. `urlsplit`, `urllib.request`
    and httpx don't, so for `evil.com\\@169.254.169.254` they connect to the
    host after the `@`. That host is returned too, as an alternate."""
    targets = [_Target(scheme, *_host_and_port(_authority(text)))]
    lenient = _lenient_authority(text)
    if lenient is not None:
        try:
            targets.append(_Target(scheme, *_host_and_port(lenient)))
        except _InvalidError:
            pass  # no client connects to an unparseable host
    return targets


def _bare_ipv6(text: str) -> bool:
    if text.count(":") < 2:
        return False
    try:
        IPv6Address(text)
    except ValueError:
        return False
    return True


def _authority(text: str) -> str:
    end = _AUTHORITY_END.search(text)
    authority = text[: end.start()] if end else text
    return authority.rpartition("@")[2]  # clients connect to what follows the last @


def _lenient_authority(text: str) -> str | None:
    """The host a client gets when a backslash doesn't end the authority, if
    that differs: only when an `@` follows a backslash."""
    end = _LENIENT_AUTHORITY_END.search(text)
    authority = text[: end.start()] if end else text
    backslash = authority.find("\\")
    if backslash == -1 or "@" not in authority[backslash:]:
        return None
    return authority.rpartition("@")[2]


def _host_and_port(authority: str) -> tuple[str, int | None, bool]:
    if authority.startswith("["):
        inside, bracket, rest = authority[1:].partition("]")
        if not bracket or (rest and not rest.startswith(":")):
            raise _InvalidError("bad_ipv6")
        return f"[{unquote(inside)}]", _port(rest[1:]), False
    host, colon, port = authority.rpartition(":")
    if not colon:
        host, port = authority, ""
    normalized, encoded = _normalize_host(host)
    return normalized, _port(port), encoded


def _port(text: str) -> int | None:
    if not text:
        return None
    if not text.isascii() or not text.isdigit() or int(text) > 65535:
        raise _InvalidError("bad_port")
    return int(text)


def _normalize_host(raw: str) -> tuple[str, bool]:
    """Decode and map the host as browsers do; report whether that changed it."""
    try:
        decoded = unquote(raw, errors="strict")
    except UnicodeDecodeError as error:
        raise _InvalidError("bad_host") from error
    mapped = unicodedata.normalize("NFKC", decoded).replace(_IDEOGRAPHIC_FULL_STOP, ".")
    host = mapped.lower()
    if _FORBIDDEN_HOST.search(host):
        raise _InvalidError("bad_host")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise _InvalidError("no_host")
    if len(host) > _MAX_HOST_LENGTH:
        raise _InvalidError("host_too_long")
    return host, mapped != raw


# --- Classifying a host ------------------------------------------------------


@dataclass(frozen=True)
class _Verdict:
    kind: DestinationKind
    form: HostForm
    reason: str
    host: str
    address: IPAddress | None = None


def _classify_host(host: str) -> _Verdict:
    if host.startswith("["):
        return _classify_ipv6(host[1:-1])
    ipv4 = _parse_ipv4(host)
    if ipv4 is not None:
        form = HostForm.IP if str(ipv4) == host else HostForm.IP_OBFUSCATED
        kind = _address_kind(ipv4)
        return _Verdict(kind, form, _address_reason(kind), str(ipv4), ipv4)
    return _classify_name(host)


def _classify_ipv6(text: str) -> _Verdict:
    try:
        address = IPv6Address(text)
    except ValueError as error:
        raise _InvalidError("bad_ipv6") from error
    embedded = _embedded_ipv4(address)
    if embedded is not None:
        kind = _address_kind(embedded)
        return _Verdict(kind, HostForm.IP_OBFUSCATED, "ipv4_in_ipv6", str(address), embedded)
    kind = _address_kind(address)
    return _Verdict(kind, HostForm.IP, _address_reason(kind), str(address), address)


def _disguised(form: HostForm) -> HostForm:
    return HostForm.IP_OBFUSCATED if form is HostForm.IP else form


def _address_reason(kind: DestinationKind) -> str:
    return f"{kind.value}_address"


# --- IPv4 as clients parse it --------------------------------------------------

_ENDS_IN_NUMBER = re.compile(r"(?:[0-9]+|0x[0-9a-f]*)")
_DIGITS = {16: re.compile(r"[0-9a-f]*"), 8: re.compile(r"[0-7]*"), 10: re.compile(r"[0-9]+")}


def _parse_ipv4(host: str) -> IPv4Address | None:
    """`host` as an IPv4 address, or None when it is a name.

    Like browsers and `inet_aton`, a host whose last label is a number is an
    address: 1 to 4 parts, each decimal, octal (leading 0) or hex (0x), and
    the last part fills the remaining bytes (`127.1` is `127.0.0.1`).
    """
    parts = host.split(".")
    if not _ENDS_IN_NUMBER.fullmatch(parts[-1]):
        return None
    if len(parts) > 4:
        raise _InvalidError("bad_ipv4")
    numbers = [_ipv4_number(part) for part in parts]
    *leading, last = numbers
    if any(number > 255 for number in leading) or last >= 256 ** (5 - len(numbers)):
        raise _InvalidError("bad_ipv4")
    value = last + sum(number << (8 * (3 - index)) for index, number in enumerate(leading))
    return IPv4Address(value)


def _ipv4_number(part: str) -> int:
    if part.startswith("0x"):
        radix, digits = 16, part[2:]
    elif len(part) > 1 and part.startswith("0"):
        radix, digits = 8, part[1:]
    else:
        radix, digits = 10, part
    if not _DIGITS[radix].fullmatch(digits):
        raise _InvalidError("bad_ipv4")
    return int(digits, radix) if digits else 0


# --- Address ranges ------------------------------------------------------------

# Instance metadata services, from each provider's documentation.
_METADATA_ADDRESSES: frozenset[IPAddress] = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, DigitalOcean, Oracle, Hetzner
        "169.254.170.2",  # AWS ECS task metadata and credentials
        "169.254.170.23",  # AWS EKS Pod Identity
        "169.254.0.23",  # Tencent Cloud
        "100.100.100.200",  # Alibaba Cloud
        "168.63.129.16",  # Azure WireServer (a public address)
        "192.0.0.192",  # Oracle Cloud, legacy
        "fd00:ec2::254",  # AWS over IPv6
        "fd00:ec2::23",  # AWS EKS Pod Identity over IPv6
    )
)


def _networks(*cidrs: str) -> tuple[IPv4Network | IPv6Network, ...]:
    return tuple(ipaddress.ip_network(cidr) for cidr in cidrs)


# Checked in order; the first range containing the address decides.
_RANGES: tuple[tuple[DestinationKind, tuple[IPv4Network | IPv6Network, ...]], ...] = (
    (DestinationKind.LOOPBACK, _networks("127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128")),
    (DestinationKind.LINK_LOCAL, _networks("169.254.0.0/16", "fe80::/10")),
    (
        DestinationKind.PRIVATE,
        _networks(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",  # carrier-grade NAT
            "fc00::/7",  # unique local
            "fec0::/10",  # site-local, deprecated but still routed by some stacks
        ),
    ),
)


def _address_kind(address: IPAddress) -> DestinationKind:
    if address in _METADATA_ADDRESSES:
        return DestinationKind.METADATA
    for kind, networks in _RANGES:
        if any(address in network for network in networks):
            return kind
    # Multicast, documentation, benchmarking and other special-purpose ranges.
    # Python counts some multicast as global, so it is excluded explicitly.
    if address.is_global and not address.is_multicast:
        return DestinationKind.EXTERNAL
    return DestinationKind.RESERVED


_NAT64 = IPv6Network("64:ff9b::/96")
_IPV4_COMPATIBLE = IPv6Network("::/96")


def _embedded_ipv4(address: IPv6Address) -> IPv4Address | None:
    """The IPv4 address an IPv6 one carries, which is where it leads."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in _NAT64 or (address in _IPV4_COMPATIBLE and int(address) > 1):
        return IPv4Address(int(address) & 0xFFFFFFFF)
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        return address.teredo[1]
    return None


# --- Names -----------------------------------------------------------------------

_METADATA_NAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",  # resolves to the metadata service inside GCP
        "instance-data",  # resolves to the metadata service inside AWS
        "instance-data.ec2.internal",
        "metadata.tencentyun.com",
    }
)
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})
# Public domains whose every subdomain resolves to 127.0.0.1.
_LOOPBACK_DOMAINS = ("localhost", "localtest.me", "lvh.me")
# Never delegated in public DNS (RFC 6761, RFC 8375, ICANN's `.internal`), or
# common internal suffixes ICANN won't delegate because of name collisions.
_INTERNAL_SUFFIXES = (
    "internal",
    "local",
    "localdomain",
    "home.arpa",
    "lan",
    "intranet",
    "corp",
    "home",
    "private",
    "svc",
)
_SPECIAL_USE_SUFFIXES = ("test", "example", "invalid")  # RFC 6761
# Wildcard DNS services that resolve a hex-encoded address in the name.
_HEX_ADDRESS_DOMAINS = ("nip.io", "sslip.io")
_DASHED_IPV4 = re.compile(r"(?<![0-9])([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})(?![0-9])")
_HEX_IPV4 = re.compile(r"(?:^|-)([0-9a-f]{8})$")


def _classify_name(host: str) -> _Verdict:
    if host in _METADATA_NAMES:
        return _Verdict(DestinationKind.METADATA, HostForm.NAME, "metadata_name", host)
    if host in _LOOPBACK_NAMES or _has_suffix(host, _LOOPBACK_DOMAINS):
        return _Verdict(DestinationKind.LOOPBACK, HostForm.NAME, "loopback_name", host)
    spelled = _spelled_internal_address(host)
    if spelled is not None:
        kind = _address_kind(spelled)
        return _Verdict(kind, HostForm.IP_IN_NAME, "address_in_name", host, spelled)
    if _has_suffix(host, _SPECIAL_USE_SUFFIXES):
        return _Verdict(DestinationKind.RESERVED, HostForm.NAME, "special_use_name", host)
    if _has_suffix(host, _INTERNAL_SUFFIXES):
        return _Verdict(DestinationKind.PRIVATE, HostForm.NAME, "internal_name", host)
    if "." not in host:
        # Completed by the resolver's search domain, so it names a local machine.
        return _Verdict(DestinationKind.PRIVATE, HostForm.NAME, "single_label_name", host)
    return _Verdict(DestinationKind.NAME, HostForm.NAME, "unresolved_name", host)


def _has_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def _spelled_internal_address(host: str) -> IPv4Address | None:
    """The most sensitive internal address written inside `host`, if any.

    Wildcard DNS services resolve `169.254.169.254.nip.io` and
    `ip-10-0-0-5.example` to the address they spell. Only internal addresses
    count: a public one spelled in a name says nothing reliable.
    """
    ranked = [
        (_INTERNAL_PRIORITY.index(kind), address)
        for address in _spelled_addresses(host)
        if (kind := _address_kind(address)) in INTERNAL_KINDS
    ]
    return min(ranked)[1] if ranked else None


def _is_octet(label: str) -> bool:
    return label.isascii() and label.isdigit() and int(label) <= 255


def _spelled_addresses(host: str) -> Iterator[IPv4Address]:
    labels = host.split(".")
    for index in range(len(labels) - 3):
        quad = labels[index : index + 4]
        if all(_is_octet(label) for label in quad):
            yield IPv4Address(".".join(str(int(label)) for label in quad))
    for match in _DASHED_IPV4.finditer(host):
        octets = [int(group) for group in match.groups()]
        if all(octet <= 255 for octet in octets):
            yield IPv4Address(".".join(map(str, octets)))
    if _has_suffix(host, _HEX_ADDRESS_DOMAINS):
        for label in labels:
            hex_match = _HEX_IPV4.search(label)
            if hex_match:
                yield IPv4Address(int(hex_match.group(1), 16))
