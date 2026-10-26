#!/usr/bin/env python3
"""Tests for skills/mail-auth/scripts/mail_auth.py.

Standard library only (unittest). Record parsers are unit-tested with no
network. End-to-end checks run against a stub DNS transport (canned
records, no sockets at all — this sandbox blocks UDP loopback, and the
suite must be hermetic anyway). The MTA-STS policy fetch over HTTPS is
best-effort and is not covered by tests.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                       / "skills" / "mail-auth" / "scripts"))

import mail_auth  # noqa: E402
from mail_auth import (Checker, Resolver, parse_dmarc_record,
                       parse_dkim_record, parse_spf_record, rsa_key_bits,
                       decode_name, encode_name, parse_response,
                       stub_answer)

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "mail-auth" / "scripts" / "mail_auth.py"

# Real RSA public keys (generated with openssl for these fixtures; public
# keys only — safe to embed). Used as DKIM p= values.
DKIM_2048_P = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbyAz1bDmK6aKE0JGj0wrys"
    "WRM6OaPdxr2zIXA0ZPWr3WNNJ2s8wASp33SkbsWPNNkl+SUGj0sXJWU7J0MWwAzjW"
    "3jfj9To8joxL9KXRjUjXhSiQuKGkfydsqTghNedIa/PoeW7/uTwXsiSvyubgXLw4C"
    "70OzDhizOgEP0nswBrjUjEAVDmKdWluOtB1drOPknSU0xdQPz6kTMgCNks2hlS0Vu"
    "RldiBmrsTzNfbGecmbYGMDfLjmrAUYvIc72w7AAaNwSQqveppfYto74jEgQzNb2Gy"
    "t77Na9jybAP5EIVx7K5rk+zcnNw7pmAH03hjzToqvRmeRRb3rjS/jHmbOPwIDAQAB")
DKIM_1024_P = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTLy8Px+5BE4vSJsy3PkBe7e8vT"
    "wsXjgo9Km8cVLwnv9pniLTSjtWiSjH7zCIoJRTQn8c3qKpEqBIfLNwisb2gjgvqt"
    "mSux5PtwYZxIgAGAbXDukBkEnwvBMoRXOJHcnvR09HQwbG1SsCpZI3UOB9F+DP9x"
    "vHXPIUDdHBK4bU4IwIDAQAB")


# ---------------------------------------------------------------------------
# Stub DNS transport (no sockets — answers from a canned zone dict)
# ---------------------------------------------------------------------------
# Zone format (also the MAIL_AUTH_DNS_STUB JSON format):
#   {"example.test|16": [{"type": 16, "text": "v=spf1 -all"}], ...}

class FakeDNS:
    def __init__(self, records):
        self.records = records

    def transport(self, packet, addr):
        return stub_answer(self.records, packet)


def resolver_for(fake):
    return Resolver([("stub", 0)], timeout=2.0, transport=fake.transport)


def run_tool(*args, zone=None):
    """Run the CLI. With `zone`, answers DNS from the canned zone via
    the MAIL_AUTH_DNS_STUB test hook instead of the network."""
    env = dict(os.environ)
    if zone is not None:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(zone, handle)
        handle.close()
        env["MAIL_AUTH_DNS_STUB"] = handle.name
        try:
            return subprocess.run(
                [sys.executable, str(SCRIPT), *args],
                capture_output=True, text=True, timeout=120, env=env)
        finally:
            os.unlink(handle.name)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=120, env=env)


# ---------------------------------------------------------------------------
# Parser unit tests (no network)
# ---------------------------------------------------------------------------

class TestParsers(unittest.TestCase):
    def test_spf_basic(self):
        parsed = parse_spf_record(
            "v=spf1 include:_spf.google.com mx -all")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["all"], "-")
        self.assertEqual(parsed["mechanisms"][0]["name"], "include")
        self.assertEqual(parsed["mechanisms"][0]["value"], "_spf.google.com")

    def test_spf_plus_all(self):
        parsed = parse_spf_record("v=spf1 +all")
        self.assertEqual(parsed["all"], "+")

    def test_spf_redirect(self):
        parsed = parse_spf_record("v=spf1 redirect=_spf.example.com")
        self.assertEqual(parsed["redirect"], "_spf.example.com")

    def test_spf_not_spf(self):
        self.assertIsNone(parse_spf_record("v=DMARC1; p=none"))
        self.assertIsNone(parse_spf_record("hello world"))

    def test_dmarc_full(self):
        parsed = parse_dmarc_record(
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
        self.assertEqual(parsed["p"], "reject")
        self.assertEqual(parsed["pct"], 100)
        self.assertEqual(parsed["rua"], "mailto:dmarc@example.com")

    def test_dmarc_none(self):
        parsed = parse_dmarc_record("v=DMARC1; p=none")
        self.assertEqual(parsed["p"], "none")
        self.assertEqual(parsed["pct"], 100)  # default

    def test_dmarc_not_dmarc(self):
        self.assertIsNone(parse_dmarc_record("v=spf1 -all"))

    def test_dkim_2048_bits(self):
        parsed = parse_dkim_record(f"v=DKIM1; k=rsa; p={DKIM_2048_P}")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["key_bits"], 2048)
        self.assertTrue(parsed["has_key"])
        self.assertFalse(parsed["testing"])

    def test_dkim_1024_bits(self):
        parsed = parse_dkim_record(f"v=DKIM1; k=rsa; p={DKIM_1024_P}")
        self.assertEqual(parsed["key_bits"], 1024)

    def test_dkim_testing_flag(self):
        parsed = parse_dkim_record(f"v=DKIM1; t=y; p={DKIM_2048_P}")
        self.assertTrue(parsed["testing"])

    def test_rsa_bits_garbage(self):
        self.assertIsNone(rsa_key_bits("not-base64!!"))
        self.assertIsNone(rsa_key_bits("AAAA"))

    def test_dns_name_roundtrip(self):
        name = "mail.example.test"
        encoded = encode_name(name)
        decoded, nxt = decode_name(encoded, 0)
        self.assertEqual(decoded, name)
        self.assertEqual(nxt, len(encoded))

    def test_dns_compressed_response(self):
        """A hand-built response where the answer NAME and the MX
        exchange are compression pointers — the parser must follow
        them. This is what real resolvers send."""
        qname = "example.test"
        question = encode_name(qname) + struct.pack(">HH", 15, 1)
        # Answer: NAME = pointer to offset 12 (the question name),
        # MX preference 10, exchange = "mail" label + pointer to 12.
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 15, 1, 300, 8)
            + struct.pack(">H", 10)
            + b"\x04mail\xc0\x0c"
        )
        msg = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
               + question + answer)
        records = parse_response(msg, 0x1234)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "example.test")
        self.assertEqual(records[0]["exchange"], "mail.example.test")
        self.assertEqual(records[0]["preference"], 10)


# ---------------------------------------------------------------------------
# End-to-end checks against the stub DNS transport
# ---------------------------------------------------------------------------

GOOD_ZONE = {
    "example.test|16": [{"type": 16,
                         "text": "v=spf1 include:_spf.a.example.test mx -all"}],
    "_spf.a.example.test|16": [{"type": 16,
                                "text": "v=spf1 ip4:192.0.2.0/24 -all"}],
    "_dmarc.example.test|16": [{"type": 16,
                                "text": "v=DMARC1; p=reject; "
                                        "rua=mailto:dmarc@example.test"}],
    "default._domainkey.example.test|16": [{"type": 16,
                                            "text": "v=DKIM1; k=rsa; "
                                                    f"p={DKIM_2048_P}"}],
    "example.test|15": [{"type": 15, "preference": 10,
                         "exchange": "mail.example.test"}],
}

BROKEN_ZONE = {
    "broken.test|16": [{"type": 16, "text": "v=spf1 +all"}],
    # no DMARC, no DKIM, no MX on purpose
}


class TestEndToEnd(unittest.TestCase):
    def test_good_domain_exits_zero(self):
        proc = run_tool("example.test", "--no-mta-sts-policy", "--json",
                        zone=GOOD_ZONE)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["counts"]["error"], 0)
        checks = {(f["check"], f["level"]) for f in summary["findings"]}
        self.assertIn(("spf", "ok"), checks)
        self.assertIn(("dmarc", "ok"), checks)
        self.assertIn(("dkim", "ok"), checks)
        self.assertIn(("mx", "ok"), checks)

    def test_broken_domain_exits_one_and_fix_plan(self):
        proc = run_tool("broken.test", "--no-mta-sts-policy", "--json",
                        "--fix", zone=BROKEN_ZONE)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        summary = json.loads(
            proc.stdout[:proc.stdout.index("\n# Fix plan")])
        self.assertGreaterEqual(summary["counts"]["error"], 2)
        self.assertIn("v=DMARC1; p=none", proc.stdout)
        self.assertIn("+all", proc.stdout)

    def test_spf_lookup_limit(self):
        """11 includes, each resolving to a record: 11 lookups, over
        the 10-lookup limit — the checker must flag it."""
        zone = {"toomany.test|16": [{"type": 16, "text":
            "v=spf1 " + " ".join(f"include:_spf{i}.toomany.test"
                                 for i in range(11)) + " -all"}]}
        for i in range(11):
            zone[f"_spf{i}.toomany.test|16"] = [
                {"type": 16, "text": "v=spf1 -all"}]
        checker = Checker(resolver_for(FakeDNS(zone)))
        checker.check_spf("toomany.test")
        errors = [f for f in checker.findings if f["level"] == "error"]
        self.assertTrue(
            any("over the 10-lookup" in f["message"] for f in errors),
            checker.findings)

    def test_spf_recursive_include_counting(self):
        """Nested includes count: a -> b -> c, each one lookup."""
        zone = {
            "nested.test|16": [{"type": 16, "text":
                "v=spf1 include:_spf.a.nested.test -all"}],
            "_spf.a.nested.test|16": [{"type": 16, "text":
                "v=spf1 include:_spf.b.nested.test -all"}],
            "_spf.b.nested.test|16": [{"type": 16, "text":
                "v=spf1 ip4:192.0.2.0/24 -all"}],
        }
        checker = Checker(resolver_for(FakeDNS(zone)))
        parsed, lookups, voids = checker.resolve_spf("nested.test")
        self.assertEqual(lookups, 2)  # two includes, no other lookups
        self.assertEqual(voids, 0)
        self.assertIsNotNone(parsed)

    def test_spf_void_lookup(self):
        """An include to a domain with no SPF record is a void lookup."""
        zone = {
            "void.test|16": [{"type": 16, "text":
                "v=spf1 include:_spf.gone.void.test -all"}],
        }
        checker = Checker(resolver_for(FakeDNS(zone)))
        parsed, lookups, voids = checker.resolve_spf("void.test")
        self.assertEqual(voids, 1)
        self.assertIsNotNone(parsed)

    def test_dkim_1024_warns(self):
        zone = {
            "old.test|16": [{"type": 16, "text": "v=spf1 -all"}],
            "default._domainkey.old.test|16": [{"type": 16, "text":
                f"v=DKIM1; k=rsa; p={DKIM_1024_P}"}],
        }
        checker = Checker(resolver_for(FakeDNS(zone)))
        checker.check_dkim("old.test")
        warns = [f for f in checker.findings if f["level"] == "warn"]
        self.assertTrue(any("1024 bits" in f["message"] for f in warns),
                        checker.findings)

    def test_dmarc_none_warns(self):
        zone = {
            "_dmarc.watch.test|16": [{"type": 16, "text":
                "v=DMARC1; p=none; rua=mailto:dmarc@watch.test"}],
        }
        checker = Checker(resolver_for(FakeDNS(zone)))
        checker.check_dmarc("watch.test")
        warns = [f for f in checker.findings if f["level"] == "warn"]
        self.assertTrue(any("p=none" in f["message"] for f in warns),
                        checker.findings)

    def test_dead_resolver_exits_two(self):
        # Nothing listens on port 1 — the pre-flight probe must fail
        # fast and report a DNS failure, not "every record missing".
        proc = run_tool("example.test", "--resolver", "127.0.0.1:1",
                        "--timeout", "0.2", "--no-mta-sts-policy")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("DNS lookup failed", proc.stderr)

    def test_recheck_loop_passing_domain(self):
        proc = run_tool("example.test", "--no-mta-sts-policy",
                        "--recheck", "2", "--interval", "0",
                        zone=GOOD_ZONE)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("0 errors", proc.stdout)


if __name__ == "__main__":
    unittest.main()
