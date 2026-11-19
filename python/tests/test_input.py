"""Client IP, rate-limit keys, email syntax, path ids, Unicode well-formedness."""

import ipaddress
import uuid

import pytest
from pydantic import ValidationError

from app.features.auth.schemas import RegisterRequest
from app.features.users.schemas import is_valid_email
from app.platform.middleware import client_ip, parse_ip, rate_limit_key
from app.platform.validation import path_uuid

PROXIES = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("::1/128"))


def scope(peer: str | None = "10.0.0.1", *forwarded: str) -> dict:
    return {
        "client": (peer, 1234) if peer else None,
        "headers": [(b"x-forwarded-for", f.encode()) for f in forwarded],
    }


# ---------- client IP ----------


def test_zero_hops_ignores_forwarded_for():
    assert client_ip(scope("10.0.0.1", "6.6.6.6"), 0) == "10.0.0.1"


def test_hops_pick_nth_from_the_right_never_the_client_controlled_left():
    s = scope("10.0.0.1", "6.6.6.6, 203.0.113.9, 198.51.100.7")
    assert client_ip(s, 1, PROXIES) == "198.51.100.7"
    assert client_ip(s, 2, PROXIES) == "203.0.113.9"
    assert client_ip(s, 3, PROXIES) == "6.6.6.6"
    assert client_ip(s, 4, PROXIES) == "10.0.0.1"  # fewer entries than hops: socket peer


def test_forwarded_for_from_an_untrusted_peer_is_ignored():
    assert client_ip(scope("192.0.2.50", "203.0.113.9"), 1, PROXIES) == "192.0.2.50"
    assert client_ip(scope("10.0.0.1", "203.0.113.9"), 1, ()) == "10.0.0.1"  # no CIDRs: nobody is trusted
    assert client_ip(scope("::1", "203.0.113.9"), 1, PROXIES) == "203.0.113.9"
    assert client_ip(scope("::ffff:10.0.0.1", "203.0.113.9"), 1, PROXIES) == "203.0.113.9"  # mapped peer


def test_non_ascii_entry_fails_alone_not_the_whole_header():
    s = {"client": ("10.0.0.1", 1), "headers": [(b"x-forwarded-for", "6.6.6.6, \u00e9vil, 203.0.113.9".encode())]}
    assert client_ip(s, 1, PROXIES) == "203.0.113.9"
    assert client_ip(s, 2, PROXIES) == "10.0.0.1"  # the non-IP entry falls back to the peer


def test_multiple_forwarded_headers_are_one_list():
    assert client_ip(scope("10.0.0.1", "6.6.6.6", "203.0.113.9"), 1, PROXIES) == "203.0.113.9"


@pytest.mark.parametrize("bad", ["not-an-ip", "", "1.2.3.4:80", "1.2.3", "[::1]", "unknown"])
def test_invalid_entry_falls_back_to_peer(bad):
    assert client_ip(scope("10.0.0.1", f"6.6.6.6, {bad}"), 1, PROXIES) == "10.0.0.1"


def test_ipv4_mapped_ipv6_is_shown_as_ipv4():
    assert client_ip(scope("::ffff:192.0.2.1"), 0) == "192.0.2.1"
    assert client_ip(scope("10.0.0.1", "::ffff:203.0.113.9"), 1, PROXIES) == "203.0.113.9"
    assert parse_ip(" 2001:DB8::1 ") == "2001:db8::1"


def test_no_usable_peer():
    assert client_ip(scope(None), 0) is None
    assert client_ip(scope("not-an-ip"), 0) is None


def test_rate_limit_key_groups_ipv6_by_64():
    assert rate_limit_key("2001:db8:1:2:aaaa::1") == rate_limit_key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert rate_limit_key("2001:db8:1:3::1") != rate_limit_key("2001:db8:1:2::1")
    assert rate_limit_key("203.0.113.9") == "203.0.113.9"
    assert rate_limit_key(None) == "unknown-peer"  # limiter-internal only, never stored as a session ip


# ---------- email ----------


@pytest.mark.parametrize(
    "email",
    ["a@example.com", "first.last+tag@sub.example.co", "o'brien@example.com", "x_y-z@ex-ample.com", "a{b}|c@d.io"],
)
def test_email_accepts(email):
    assert is_valid_email(email)


@pytest.mark.parametrize(
    "email",
    [
        "victim<attacker@evil.example>",
        '"a b"@example.com',
        "a@b",
        "a@@example.com",
        "josé@example.com",
        "a b@example.com",
        "a@exa_mple.com",
        "a@example.com\n",
        "a@example..com",
        "a@example.com.",
        "a\x00b@example.com",
        "A@example.com",  # must already be lowercased
        f"{'a' * 245}@example.com",  # 257 > 254
    ],
)
def test_email_rejects(email):
    assert not is_valid_email(email)


def test_register_normalises_before_checking():
    body = RegisterRequest(email="  Ada@Example.COM ", password="correct horse battery", name=" Ada ")
    assert (body.email, body.name) == ("ada@example.com", "Ada")


# ---------- path ids and Unicode ----------


def test_path_uuid_canonical_form_only():
    u = uuid.uuid4()
    assert path_uuid(str(u)) == u
    assert path_uuid(str(u).upper()) == u
    for bad in (u.hex, f"{{{u}}}", f"urn:uuid:{u}", f" {u}", f"{u}\n", "not-a-uuid", ""):
        assert path_uuid(bad) is None


def test_lone_surrogate_is_a_validation_error_not_a_crash():
    with pytest.raises(ValidationError, match="well-formed Unicode"):
        RegisterRequest(email="a@example.com", password="correct horse", name="A\ud800")
    with pytest.raises(ValidationError, match="well-formed Unicode"):
        RegisterRequest(email="a@example.com", password="pass\udfffword", name="A")
