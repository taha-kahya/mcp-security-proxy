"""The destination classifier labels where a URL or host points, from text alone."""

from __future__ import annotations

from ipaddress import ip_address

import pytest

from mcp_security_proxy.sdk import Destination, DestinationKind, HostForm, classify_destination

METADATA = DestinationKind.METADATA
LOOPBACK = DestinationKind.LOOPBACK
LINK_LOCAL = DestinationKind.LINK_LOCAL
PRIVATE = DestinationKind.PRIVATE
RESERVED = DestinationKind.RESERVED
EXTERNAL = DestinationKind.EXTERNAL
NAME = DestinationKind.NAME
INVALID = DestinationKind.INVALID


@pytest.mark.parametrize(
    ("value", "form"),
    [
        ("http://169.254.169.254/latest/meta-data/", HostForm.IP),
        ("169.254.169.254", HostForm.IP),
        ("http://169.254.169.254./", HostForm.IP),
        ("HTTP://169.254.169.254/", HostForm.IP),
        ("http://2852039166/", HostForm.IP_OBFUSCATED),  # one decimal number
        ("http://0xA9FEA9FE/", HostForm.IP_OBFUSCATED),  # one hex number
        ("http://0xa9.0xfe.0xa9.0xfe/", HostForm.IP_OBFUSCATED),
        ("http://0251.0376.0251.0376/", HostForm.IP_OBFUSCATED),  # octal
        ("http://169.254.43518/", HostForm.IP_OBFUSCATED),  # last part fills the rest
        ("http://169.16689662/", HostForm.IP_OBFUSCATED),
        ("http://169%2e254%2e169%2e254/", HostForm.IP_OBFUSCATED),
        ("http://１６９．２５４．１６９．２５４/", HostForm.IP_OBFUSCATED),  # fullwidth
        ("http://169。254。169。254/", HostForm.IP_OBFUSCATED),  # ideographic stops
        ("http://[::ffff:169.254.169.254]/", HostForm.IP_OBFUSCATED),
        ("http://[::ffff:a9fe:a9fe]/", HostForm.IP_OBFUSCATED),
        ("http://[64:ff9b::a9fe:a9fe]/", HostForm.IP_OBFUSCATED),  # NAT64
        ("http://[2002:a9fe:a9fe::]/", HostForm.IP_OBFUSCATED),  # 6to4
        ("http://169.254.169.254.nip.io/", HostForm.IP_IN_NAME),
        ("http://app.169-254-169-254.sslip.io/", HostForm.IP_IN_NAME),
        ("http://a9fea9fe.nip.io/", HostForm.IP_IN_NAME),
    ],
)
def test_every_spelling_of_the_metadata_address_is_metadata(value: str, form: HostForm) -> None:
    destination = classify_destination(value)

    assert destination.kind is METADATA
    assert destination.form is form
    assert destination.address == ip_address("169.254.169.254")
    assert destination.is_internal


@pytest.mark.parametrize(
    "value",
    [
        "http://user@169.254.169.254/",
        "http://trusted.example.com@169.254.169.254/",
        "http://a@b@169.254.169.254/",  # clients connect after the last @
        "http://1.2.3.4:80@169.254.169.254/",
        "http:\\\\169.254.169.254\\latest",  # backslashes act as slashes
        "http:/169.254.169.254/",
        "http:169.254.169.254",
        "  http://169.254.169.254  ",
        "http://169.254.\n169.254/",  # tabs and newlines are removed
    ],
)
def test_url_tricks_that_clients_resolve_to_the_metadata_address(value: str) -> None:
    assert classify_destination(value).kind is METADATA


@pytest.mark.parametrize(
    "value",
    [
        "http://169.254.170.2/v2/credentials",  # AWS ECS
        "http://169.254.170.23/",  # AWS EKS Pod Identity
        "http://[fd00:ec2::254]/",  # AWS over IPv6
        "http://[fd00:ec2::23]/",
        "http://100.100.100.200/",  # Alibaba
        "http://168.63.129.16/",  # Azure WireServer, a public address
        "http://192.0.0.192/",  # Oracle
        "http://169.254.0.23/",  # Tencent
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://METADATA.GOOGLE.INTERNAL./",
        "http://metadata.goog/",
        "http://metadata/",
        "http://instance-data/latest/",
        "http://metadata.tencentyun.com/",
    ],
)
def test_metadata_services_of_each_cloud(value: str) -> None:
    assert classify_destination(value).kind is METADATA


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("http://127.0.0.1:8080/", LOOPBACK),
        ("http://127.1/", LOOPBACK),
        ("http://127.255.0.9/", LOOPBACK),
        ("http://0.0.0.0:8000/", LOOPBACK),  # Linux connects to the local host
        ("http://0/", LOOPBACK),
        ("http://[::1]/", LOOPBACK),
        ("http://[::]/", LOOPBACK),
        ("::1", LOOPBACK),
        ("http://localhost/", LOOPBACK),
        ("localhost:8080", LOOPBACK),
        ("http://api.localhost/", LOOPBACK),
        ("http://app.localtest.me/", LOOPBACK),
        ("http://lvh.me/", LOOPBACK),
        ("file:///etc/passwd", LOOPBACK),
        ("file://localhost/etc/passwd", LOOPBACK),
        ("file:/etc/passwd", LOOPBACK),
        ("http://169.254.1.1/", LINK_LOCAL),
        ("http://[fe80::1]/", LINK_LOCAL),
        ("[fe80::1%25eth0]", LINK_LOCAL),
        ("fe80::1", LINK_LOCAL),
        ("http://10.0.0.5/", PRIVATE),
        ("10.0.0.1:5432", PRIVATE),
        ("http://172.16.0.1/", PRIVATE),
        ("http://172.31.255.255/", PRIVATE),
        ("http://192.168.1.1/", PRIVATE),
        ("http://100.64.0.1/", PRIVATE),  # carrier-grade NAT
        ("http://[fd12:3456::1]/", PRIVATE),
        ("http://[::ffff:10.0.0.1]/", PRIVATE),
        ("redis://10.0.0.1:6379", PRIVATE),
        ("gopher://127.0.0.1:70/_", LOOPBACK),
        ("http://224.0.0.1/", RESERVED),
        ("http://[ff02::1]/", RESERVED),
        ("http://255.255.255.255/", RESERVED),
        ("http://240.0.0.1/", RESERVED),
        ("http://192.0.2.1/", RESERVED),
        ("http://198.18.0.1/", RESERVED),
        ("http://203.0.113.9/", RESERVED),
        ("http://[2001:db8::1]/", RESERVED),
        ("http://0.1.2.3/", RESERVED),
        ("https://8.8.8.8/", EXTERNAL),
        ("https://1.1.1.1:443/dns-query", EXTERNAL),
        ("https://[2606:4700::1111]/", EXTERNAL),
        ("http://172.32.0.1/", EXTERNAL),
        ("http://[::ffff:8.8.8.8]/", EXTERNAL),
    ],
)
def test_addresses_get_the_label_of_their_range(value: str, kind: DestinationKind) -> None:
    assert classify_destination(value).kind is kind


@pytest.mark.parametrize(
    ("value", "kind", "reason"),
    [
        ("http://db.internal/", PRIVATE, "internal_name"),
        ("http://ip-10-0-0-5.ec2.internal/", PRIVATE, "address_in_name"),
        ("http://printer.local/", PRIVATE, "internal_name"),
        ("http://web.svc.cluster.local/", PRIVATE, "internal_name"),
        ("http://nas.home.arpa/", PRIVATE, "internal_name"),
        ("http://wiki.corp/", PRIVATE, "internal_name"),
        ("http://router.lan/", PRIVATE, "internal_name"),
        ("http://intranet/", PRIVATE, "internal_name"),
        ("http://wiki/", PRIVATE, "single_label_name"),
        ("redis:6379", PRIVATE, "single_label_name"),
        ("http://site.test/", RESERVED, "special_use_name"),
        ("http://nothing.invalid/", RESERVED, "special_use_name"),
        ("http://10.0.0.5.nip.io/", PRIVATE, "address_in_name"),
        ("http://127.0.0.1.sslip.io/", LOOPBACK, "address_in_name"),
    ],
)
def test_internal_names(value: str, kind: DestinationKind, reason: str) -> None:
    destination = classify_destination(value)

    assert (destination.kind, destination.reason) == (kind, reason)


@pytest.mark.parametrize(
    "value",
    [
        "https://api.github.com/repos",
        "https://example.com",
        "https://hooks.slack.com/services/T000/B000/XXX",
        "http://ec2-54-1-2-3.compute-1.amazonaws.com/",  # spells a public address
        "http://8.8.8.8.nip.io/",
        "https://v1.2.3.4.example.com/",
        "https://git-deadbeef.example.com/",  # hex only counts on wildcard DNS domains
        "https://deadbeef.example.com/",
        "https://metadata.example.com/",
        "https://localhost.example.com/",
        "https://internal.example.com/",
        "https://my.local.example.com/",
        "https://bücher.de/",
    ],
)
def test_public_looking_names_stay_unresolved_never_external(value: str) -> None:
    destination = classify_destination(value)

    assert destination.kind is NAME
    assert destination.form is HostForm.NAME
    assert not destination.is_internal


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("http://", "no_host"),
        ("mailto:someone@example.com", "no_host"),
        ("javascript:alert(1)", "no_host"),
        ("data:text/plain,hi", "no_host"),
        ("http://1.2.3.256/", "bad_ipv4"),
        ("http://1.2.3.4.5/", "bad_ipv4"),
        ("http://09.1.1.1/", "bad_ipv4"),  # 9 is not an octal digit
        ("http://256.1/", "bad_ipv4"),
        ("http://[::1/", "bad_ipv6"),
        ("http://[not-ipv6]/", "bad_ipv6"),
        ("http://[::1]x/", "bad_ipv6"),
        ("http://fd00:ec2::254/", "bad_host"),  # IPv6 needs brackets in a URL
        ("http://example.com:99999/", "bad_port"),
        ("http://example.com:8o/", "bad_port"),
        ("http://exa mple.com/", "bad_host"),
        ("http://169.254.169.254%00.example.com/", "bad_host"),
        ("http://example.com%2Fx/", "bad_host"),  # an encoded slash
        ("http://example.com／evil/", "bad_host"),  # fullwidth solidus maps to /
        ("http://%ff/", "bad_host"),
        ("http://" + "a" * 254 + "/", "host_too_long"),
    ],
)
def test_unparseable_input_is_invalid_not_external(value: str, reason: str) -> None:
    destination = classify_destination(value)

    assert destination.kind is INVALID
    assert destination.reason == reason
    assert not destination.is_internal


def test_a_host_is_an_address_only_when_its_last_label_is_a_number() -> None:
    assert classify_destination("http://0x1g/").reason == "single_label_name"
    assert classify_destination("http://0x1g.example.com/").kind is NAME


def test_url_parts_are_reported() -> None:
    assert classify_destination("HTTPS://User:pw@API.Example.COM:8443/x?y#z") == Destination(
        NAME, HostForm.NAME, "unresolved_name", "api.example.com", None, "https", 8443
    )


def test_ip_destinations_report_the_canonical_address() -> None:
    destination = classify_destination("http://0x7f.1:8080/")

    assert destination.host == "127.0.0.1"
    assert destination.address == ip_address("127.0.0.1")
    assert destination.port == 8080


def test_ipv4_in_ipv6_keeps_the_ipv6_host_and_reports_the_ipv4_address() -> None:
    destination = classify_destination("http://[::ffff:10.0.0.1]/")

    assert destination.host == "::ffff:10.0.0.1"  # RFC 5952, on every Python version
    assert destination.address == ip_address("10.0.0.1")
    assert destination.reason == "ipv4_in_ipv6"


def test_special_schemes_skip_any_number_of_slashes_like_browsers() -> None:
    assert classify_destination("http:///10.0.0.1/").kind is PRIVATE


def test_only_the_host_decides_not_the_path_query_or_fragment() -> None:
    for value in (
        "https://example.com/?next=http://169.254.169.254/",
        "https://example.com/#@169.254.169.254",
        "https://example.com?@169.254.169.254",
        "https://example.com/169.254.169.254",
    ):
        assert classify_destination(value).kind is NAME


@pytest.mark.parametrize(
    ("value", "kind", "host"),
    [
        # WHATWG ends the authority at the backslash (host evil.com);
        # urlsplit, urllib.request and httpx connect to the host after the @.
        ("http://evil.com\\@169.254.169.254/", METADATA, "169.254.169.254"),
        ("http://evil.com:80\\@169.254.169.254/", METADATA, "169.254.169.254"),
        ("http://user@evil.com\\@127.0.0.1/", DestinationKind.LOOPBACK, "127.0.0.1"),
        ("evil.com\\@10.0.0.1", DestinationKind.PRIVATE, "10.0.0.1"),
        ("http://evil.com\\@metadata.google.internal/", METADATA, "metadata.google.internal"),
        # The WHATWG reading is invalid (port `pw`, a space in the host, a port
        # past 65535), but the other reading still connects to the @ host.
        ("http://user:pw\\@169.254.169.254/", METADATA, "169.254.169.254"),
        ("http://evil.com \\@169.254.169.254/", METADATA, "169.254.169.254"),
        ("http://a:99999\\@169.254.169.254/", METADATA, "169.254.169.254"),
    ],
)
def test_a_backslash_before_an_at_classifies_both_readings(
    value: str, kind: DestinationKind, host: str
) -> None:
    destination = classify_destination(value)

    assert (destination.kind, destination.host) == (kind, host)
    assert destination.reason == "ambiguous_authority"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("http://evil.com\\path", "unresolved_name"),  # no @: one reading only
        ("http://evil.com\\@8.8.8.8/", "unresolved_name"),  # neither reading is internal
        (
            "http://10.0.0.1\\@8.8.8.8/",
            "private_address",
        ),  # the WHATWG reading is the sensitive one
        ("http://evil.com/\\@169.254.169.254", "unresolved_name"),  # the @ is in the path
        ("http://a:b\\@evil.com/", "bad_port"),  # the other reading isn't internal
        ("http://a:b\\@evil.com:x/", "bad_port"),  # neither reading parses
    ],
)
def test_an_ambiguous_authority_changes_the_label_only_when_more_sensitive(
    value: str, reason: str
) -> None:
    assert classify_destination(value).reason == reason


def test_the_most_sensitive_spelled_address_wins() -> None:
    destination = classify_destination("http://10.0.0.1.169-254-169-254.nip.io/")

    assert destination.kind is METADATA


def test_is_internal_covers_exactly_the_internal_kinds() -> None:
    internal = {
        kind for kind in DestinationKind if Destination(kind, HostForm.NONE, "test").is_internal
    }

    assert internal == {METADATA, LOOPBACK, LINK_LOCAL, PRIVATE}


def test_destinations_are_immutable_and_hashable() -> None:
    destination = classify_destination("http://10.0.0.1/")

    assert hash(destination) == hash(classify_destination("http://10.0.0.1/"))
    with pytest.raises(AttributeError):
        destination.kind = EXTERNAL  # type: ignore[misc]
