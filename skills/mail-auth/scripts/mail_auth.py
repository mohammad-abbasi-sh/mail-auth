#!/usr/bin/env python3
"""mail_auth — check a domain's email authentication (SPF / DKIM / DMARC)
as a deterministic, zero-dependency tool.

Pure Python standard library: the DNS client is implemented from scratch
over UDP (no `dnspython`, no `dig` subprocess), so the tool works anywhere
Python runs and its tests can run against a fake DNS server on localhost.

What it checks (see references/dns-records.md for what each record means):
    SPF       v=spf1 present? lookup count vs the 10-lookup limit,
              void lookups, `all` qualifier (+all is a hole, -all is strict)
    DMARC     _dmarc TXT present? p= policy (none/quarantine/reject),
              pct, rua reporting address
    DKIM      probe common selectors at <selector>._domainkey, report
              found keys with key size (<1024 weak, 1024 dated, 2048+ good)
    MX        mail exchangers present? (info only — a send-only domain
              legitimately has none)
    MTA-STS   _mta-sts TXT present? policy fetched best-effort over HTTPS
    TLS-RPT   _smtp._tls TXT present? (info only)

Exit codes:
    0  no errors (warnings are fine, unless --strict)
    1  errors found — see the report
    2  usage error, or the DNS resolver did not answer at all

The tool never invents a provider's include or a DKIM key: --fix prints
the exact records to publish, with placeholders where only the mail
provider's value will do. And passing authentication is necessary, not
sufficient, for inbox placement — reputation, engagement and volume
still decide whether Gmail delivers to the inbox or to spam.

Usage:
    python3 mail_auth.py <domain> [--resolver 1.1.1.1] [--json]
                            [--fix] [--recheck N] [--interval S]
                            [--strict] [--timeout SECS]
"""
import argparse
import base64
import binascii
import json
import re
import socket
import struct
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_TIMEOUT = 5.0
MAX_LOOKUPS = 10          # RFC 7208: SPF evaluation must stop after 10 lookups
MAX_VOID_LOOKUPS = 2      # RFC 7208: at most 2 void (empty) lookups
MAX_SPF_DEPTH = 10        # recursion cap for include:/redirect:
MAX_DNS_RETRIES = 2

# Selectors probed for DKIM (vamp-mail-audit probes 15; this list is the
# same idea — the common selectors providers actually use).
DEFAULT_SELECTORS = [
    "default", "google", "mail", "mailchimp", "mandrill", "sendgrid",
    "s1", "s2", "selector1", "selector2", "k1", "k2", "dkim", "email",
    "key1",
]

# DNS types
TYPE_A = 1
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16

QTYPE_NAMES = {TYPE_A: "A", TYPE_CNAME: "CNAME", TYPE_MX: "MX",
               TYPE_TXT: "TXT"}


class DNSError(Exception):
    """The resolver did not answer, or the response was unusable."""


# --------------------------------------------------------------------------
# Minimal DNS client (RFC 1035, UDP, stdlib only)
# --------------------------------------------------------------------------

def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise DNSError(f"label too long in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def decode_name(msg, off):
    """Decode a possibly compressed domain name. Returns (name, next_off)."""
    labels = []
    jumped = False
    end = None
    guard = 0
    while True:
        guard += 1
        if guard > 128 or off >= len(msg):
            raise DNSError("malformed name in DNS response")
        length = msg[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            off = pointer
            continue
        if length & 0xC0:
            raise DNSError("bad label length in DNS response")
        labels.append(msg[off + 1:off + 1 + length].decode("utf-8", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def build_query(qname, qtype, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(qname) + struct.pack(">HH", qtype, 1)


def parse_txt_rdata(rdata):
    """TXT rdata is a sequence of length-prefixed character-strings."""
    parts = []
    off = 0
    while off < len(rdata):
        length = rdata[off]
        parts.append(rdata[off + 1:off + 1 + length])
        off += 1 + length
    return b"".join(parts).decode("utf-8", "replace")


def parse_response(msg, qid):
    """Parse a DNS response into a list of answer dicts."""
    if len(msg) < 12:
        raise DNSError("DNS response too short")
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise DNSError("DNS response id does not match the query")
    if flags & 0x000F != 0:
        raise DNSError(f"DNS error, rcode {flags & 0x000F}")
    off = 12
    for _ in range(qd):
        _, off = decode_name(msg, off)
        off += 4
    answers = []
    for _ in range(an + ns + ar):
        if off >= len(msg):
            break
        name, off = decode_name(msg, off)
        if off + 10 > len(msg):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        record = {"name": name, "type": rtype, "ttl": ttl}
        if rtype == TYPE_TXT:
            record["text"] = parse_txt_rdata(rdata)
        elif rtype == TYPE_MX:
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = decode_name(msg, off - rdlen + 2)
            record["preference"] = preference
            record["exchange"] = exchange
        elif rtype == TYPE_CNAME:
            target, _ = decode_name(msg, off - rdlen)
            record["target"] = target
        answers.append(record)
    return answers


def udp_transport(packet, addr, timeout):
    """Send one DNS query over UDP and return the raw response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, addr)
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


class Resolver:
    """DNS resolver trying each server in order.

    `transport` is an injectable callable taking (packet, (host, port))
    and returning raw response bytes — the default is UDP. Tests inject
    a stub transport so the suite runs without any network (and without
    UDP, which some sandboxes block).
    """

    def __init__(self, servers, timeout=DEFAULT_TIMEOUT, transport=None):
        # servers: list of (host, port)
        self.servers = servers
        self.timeout = timeout
        self.transport = transport

    @classmethod
    def system(cls, timeout=DEFAULT_TIMEOUT):
        servers = []
        try:
            for line in Path("/etc/resolv.conf").read_text(
                    encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append((parts[1], 53))
        except OSError:
            pass
        if not servers:
            servers = [("1.1.1.1", 53), ("8.8.8.8", 53)]
        return cls(servers, timeout)

    def query(self, qname, qtype):
        """Return the answer records, or raise DNSError."""
        last_error = DNSError("no DNS server configured")
        for host, port in self.servers:
            for attempt in range(MAX_DNS_RETRIES + 1):
                qid = int.from_bytes(__import__("os").urandom(2), "big")
                packet = build_query(qname, qtype, qid)
                try:
                    if self.transport is not None:
                        data = self.transport(packet, (host, port))
                    else:
                        data = udp_transport(packet, (host, port),
                                             self.timeout)
                    return parse_response(data, qid)
                except (socket.timeout, OSError, DNSError) as exc:
                    last_error = DNSError(f"{host}:{port}: {exc}")
        raise last_error

    def txt_records(self, qname):
        return [a["text"] for a in self.query(qname, TYPE_TXT)
                if a["type"] == TYPE_TXT]


# --------------------------------------------------------------------------
# Test hook: stub DNS transport from a JSON zone file
# --------------------------------------------------------------------------
# Set MAIL_AUTH_DNS_STUB to a JSON file to answer every query from canned
# records instead of the network. Format:
#   {"example.test|16": [{"type": 16, "text": "v=spf1 -all"}],
#    "example.test|15": [{"type": 15, "preference": 10,
#                         "exchange": "mail.example.test"}]}
# Unknown names get an empty NOERROR answer. This exists so the test
# suite (and offline demos) can run with no network at all; it is not
# part of normal operation.

def build_txt_rdata(text):
    raw = text.encode("utf-8")
    out = bytearray()
    for i in range(0, len(raw), 255):
        chunk = raw[i:i + 255]
        out.append(len(chunk))
        out.extend(chunk)
    return bytes(out)


def stub_answer(records, packet):
    """Build a wire-format DNS response for `packet` from `records`."""
    qid = struct.unpack(">H", packet[:2])[0]
    qname, off = decode_name(packet, 12)
    qtype, _ = struct.unpack(">HH", packet[off:off + 4])
    question = packet[12:off + 4]
    answers = records.get(f"{qname.lower()}|{qtype}", [])
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, len(answers), 0, 0)
    body = bytearray(question)
    for record in answers:
        rtype = record["type"]
        if rtype == TYPE_TXT:
            rdata = build_txt_rdata(record["text"])
        elif rtype == TYPE_MX:
            rdata = struct.pack(">H", record["preference"]) + encode_name(
                record["exchange"])
        else:
            continue
        body += encode_name(qname)
        body += struct.pack(">HHIH", rtype, 1, 300, len(rdata))
        body += rdata
    return header + bytes(body)


def load_stub_transport(path):
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    return lambda packet, addr: stub_answer(records, packet)


# --------------------------------------------------------------------------
# Record parsers (pure functions — unit-tested without any network)
# --------------------------------------------------------------------------

SPF_MECH_RE = re.compile(
    r"^([+\-~?])?(include|a|mx|ptr|exists|ip4|ip6|all)(?::(\S+))?$")
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}


def parse_spf_record(text):
    """Parse one v=spf1 record. Returns a dict, or None if not SPF."""
    tokens = text.strip().split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return None
    mechanisms = []
    redirect = None
    for token in tokens[1:]:
        if token.lower().startswith("redirect="):
            redirect = token.split("=", 1)[1]
            continue
        if "=" in token and not token.startswith(("ip4:", "ip6:")):
            continue  # other modifiers (exp=, etc.) — not lookup-relevant
        match = SPF_MECH_RE.match(token)
        if not match:
            continue
        qualifier, name, value = match.groups()
        mechanisms.append({
            "qualifier": qualifier or "+",
            "name": name,
            "value": value,
        })
    all_mech = next((m for m in mechanisms if m["name"] == "all"), None)
    return {
        "mechanisms": mechanisms,
        "redirect": redirect,
        "all": all_mech["qualifier"] if all_mech else None,
    }


def parse_dmarc_record(text):
    """Parse one v=DMARC1 record. Returns a dict, or None if not DMARC."""
    fields = {}
    for part in text.strip().split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.strip().lower()] = value.strip()
    if fields.get("v", "").upper() != "DMARC1":
        return None
    try:
        pct = int(fields.get("pct", "100"))
    except ValueError:
        pct = 100
    return {
        "p": fields.get("p"),
        "sp": fields.get("sp"),
        "pct": pct,
        "rua": fields.get("rua"),
        "ruf": fields.get("ruf"),
        "adkim": fields.get("adkim", "r"),
        "aspf": fields.get("aspf", "r"),
    }


def der_read_tlv(data, off):
    """Read one DER tag-length-value. Returns (tag, value_bytes, next_off)."""
    if off >= len(data):
        raise ValueError("truncated DER")
    tag = data[off]
    off += 1
    length = data[off]
    off += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    return tag, data[off:off + length], off + length


def rsa_key_bits(p_b64):
    """Bit length of the RSA modulus in a DKIM p= value (base64 DER
    SubjectPublicKeyInfo). Returns None if the key cannot be parsed."""
    try:
        der = base64.b64decode(p_b64, validate=True)
        _, spki, _ = der_read_tlv(der, 0)          # SEQUENCE
        _, _, off = der_read_tlv(spki, 0)          # SEQUENCE (algorithm)
        _, bitstring, _ = der_read_tlv(spki, off)  # BIT STRING
        if not bitstring or bitstring[0] != 0:
            return None
        _, rsapub, _ = der_read_tlv(bitstring, 1)  # SEQUENCE
        _, modulus, _ = der_read_tlv(rsapub, 0)    # INTEGER modulus
        modulus = modulus.lstrip(b"\x00")
        if not modulus:
            return None
        return (len(modulus) - 1) * 8 + modulus[0].bit_length()
    except (ValueError, binascii.Error, IndexError):
        return None


def parse_dkim_record(text):
    """Parse one DKIM TXT record. Returns a dict, or None if not DKIM."""
    fields = {}
    for part in text.strip().split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.strip().lower()] = value.strip()
    if fields.get("v", "").upper() != "DKIM1":
        return None
    p_value = re.sub(r"\s+", "", fields.get("p", ""))
    bits = rsa_key_bits(p_value) if p_value else None
    return {
        "key_type": fields.get("k", "rsa"),
        "key_bits": bits,
        "testing": "y" in fields.get("t", ""),
        "has_key": bool(p_value),
    }


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

class Checker:
    def __init__(self, resolver, selectors=None):
        self.resolver = resolver
        self.selectors = selectors or DEFAULT_SELECTORS
        self.findings = []

    def add(self, check, level, message, detail=None):
        finding = {"check": check, "level": level, "message": message}
        if detail:
            finding["detail"] = detail
        self.findings.append(finding)

    # -- SPF ---------------------------------------------------------------
    def resolve_spf(self, domain, depth=0, cache=None):
        """Fetch and resolve one domain's SPF, counting lookups.

        Returns (parsed_record_or_None, lookups, void_lookups).
        `lookups` counts every DNS query the evaluation caused, so the
        10-lookup limit is measured the way receivers measure it.
        """
        cache = cache if cache is not None else {}
        if domain in cache:
            return cache[domain]
        if depth > MAX_SPF_DEPTH:
            return None, 0, 0
        try:
            texts = self.resolver.txt_records(domain)
        except DNSError:
            return None, 0, 1  # no answer at all counts as a void lookup
        parsed = None
        for text in texts:
            parsed = parse_spf_record(text)
            if parsed is not None:
                break
        if parsed is None:
            result = (None, 0, 1)
            cache[domain] = result
            return result
        lookups = 0
        voids = 0
        for mech in parsed["mechanisms"]:
            if mech["name"] not in LOOKUP_MECHANISMS:
                continue
            lookups += 1
            if mech["name"] == "include" and mech["value"]:
                _, sub_lookups, sub_voids = self.resolve_spf(
                    mech["value"], depth + 1, cache)
                lookups += sub_lookups
                voids += sub_voids
        if parsed["redirect"]:
            lookups += 1
            _, sub_lookups, sub_voids = self.resolve_spf(
                parsed["redirect"], depth + 1, cache)
            lookups += sub_lookups
            voids += sub_voids
        result = (parsed, lookups, voids)
        cache[domain] = result
        return result

    def check_spf(self, domain):
        try:
            parsed, lookups, voids = self.resolve_spf(domain)
        except DNSError as exc:
            self.add("spf", "error", f"SPF lookup failed: {exc}")
            return None
        if parsed is None:
            self.add(
                "spf", "error",
                "No SPF record found.",
                "Publish a TXT record: v=spf1 include:<your-provider> -all "
                "(replace <your-provider> with your mail provider's "
                "documented include). Without SPF, anyone can send mail "
                "that claims to be from this domain.")
            return None
        self.add("spf", "ok",
                 f"SPF record present ({lookups} DNS lookups).")
        if lookups > MAX_LOOKUPS:
            self.add(
                "spf", "error",
                f"SPF causes {lookups} DNS lookups — over the 10-lookup "
                "limit, so receivers stop evaluating and treat the result "
                "as a permanent error.",
                "Remove or flatten include: mechanisms (each include: "
                "costs one lookup, plus everything inside it).")
        if voids > MAX_VOID_LOOKUPS:
            self.add(
                "spf", "warn",
                f"SPF causes {voids} void lookups (mechanisms that resolve "
                "to nothing) — the limit is 2.")
        qualifier = parsed["all"]
        if qualifier == "+":
            self.add(
                "spf", "error",
                "SPF ends in +all — it authorises the whole internet to "
                "send as this domain. The record is worse than useless.",
                "Change +all to -all (strict) or ~all (softfail while "
                "testing).")
        elif qualifier == "~":
            self.add(
                "spf", "warn",
                "SPF ends in ~all (softfail). Receivers usually accept the "
                "mail anyway — move to -all once legitimate senders are "
                "covered.")
        elif qualifier == "?":
            self.add("spf", "warn",
                     "SPF ends in ?all (neutral) — receivers learn nothing "
                     "from it. Prefer -all.")
        elif qualifier is None:
            self.add("spf", "warn",
                     "SPF has no `all` mechanism — receivers fall back to "
                     "neutral. Add -all at the end.")
        elif qualifier == "-":
            self.add("spf", "ok", "SPF ends in -all (strict fail).")
        return parsed

    # -- DMARC -------------------------------------------------------------
    def check_dmarc(self, domain):
        qname = f"_dmarc.{domain}"
        try:
            texts = self.resolver.txt_records(qname)
        except DNSError as exc:
            self.add("dmarc", "error", f"DMARC lookup failed: {exc}")
            return None
        parsed = None
        for text in texts:
            parsed = parse_dmarc_record(text)
            if parsed is not None:
                break
        if parsed is None:
            self.add(
                "dmarc", "error",
                "No DMARC record found.",
                f"Publish TXT _dmarc: v=DMARC1; p=none; "
                f"rua=mailto:dmarc@{domain} — start in monitoring mode, "
                "then move to quarantine, then reject once the reports "
                "show no legitimate mail is affected.")
            return None
        policy = parsed["p"]
        if policy is None:
            self.add("dmarc", "error",
                     "DMARC record has no p= policy.",
                     "Add p=none to start (monitoring), then quarantine, "
                     "then reject.")
        elif policy == "none":
            self.add(
                "dmarc", "warn",
                "DMARC policy is p=none — monitoring only, receivers take "
                "no action on failing mail.",
                "Move to p=quarantine, then p=reject, once the aggregate "
                "reports show no legitimate mail is affected.")
        elif policy == "quarantine":
            self.add("dmarc", "ok",
                     "DMARC policy is p=quarantine" +
                     ("" if parsed["pct"] == 100 else
                      f" (pct={parsed['pct']})."))
        elif policy == "reject":
            self.add("dmarc", "ok",
                     "DMARC policy is p=reject" +
                     ("" if parsed["pct"] == 100 else
                      f" (pct={parsed['pct']} — only {parsed['pct']}% of "
                      "failing mail is rejected)."))
        else:
            self.add("dmarc", "error",
                     f"DMARC policy p={policy!r} is not a valid policy "
                     "(use none, quarantine, or reject).")
        if not parsed["rua"]:
            self.add("dmarc", "warn",
                     "DMARC has no rua= reporting address — you will never "
                     "see who is failing or abusing the domain.",
                     f"Add rua=mailto:dmarc@{domain}.")
        else:
            self.add("dmarc", "ok",
                     f"DMARC aggregate reports go to {parsed['rua']}.")
        return parsed

    # -- DKIM --------------------------------------------------------------
    def check_dkim(self, domain):
        found = []
        for selector in self.selectors:
            qname = f"{selector}._domainkey.{domain}"
            try:
                texts = self.resolver.txt_records(qname)
            except DNSError:
                continue
            for text in texts:
                parsed = parse_dkim_record(text)
                if parsed is None:
                    continue
                parsed["selector"] = selector
                found.append(parsed)
        if not found:
            self.add(
                "dkim", "warn",
                "No DKIM key found for any probed selector "
                f"({', '.join(self.selectors[:5])}, …).",
                "DKIM keys come from your mail provider — ask it for the "
                "selector and public key, then publish it as TXT "
                "<selector>._domainkey. The tool cannot invent a key.")
            return []
        for key in found:
            bits = key["key_bits"]
            if not key["has_key"]:
                self.add("dkim", "error",
                         f"DKIM selector {key['selector']}: record has no "
                         "p= public key.")
            elif bits is None:
                self.add("dkim", "warn",
                         f"DKIM selector {key['selector']}: public key "
                         "could not be parsed.")
            elif bits < 1024:
                self.add("dkim", "error",
                         f"DKIM selector {key['selector']}: key is "
                         f"{bits} bits — below the 1024-bit minimum.",
                         "Generate a 2048-bit key with your provider and "
                         "publish the new selector.")
            elif bits < 2048:
                self.add("dkim", "warn",
                         f"DKIM selector {key['selector']}: key is "
                         f"{bits} bits — works, but 2048 bits is the "
                         "current recommendation.",
                         "Rotate to a 2048-bit key when convenient.")
            else:
                self.add("dkim", "ok",
                         f"DKIM selector {key['selector']}: {bits}-bit key.")
            if key["testing"]:
                self.add("dkim", "warn",
                         f"DKIM selector {key['selector']}: t=y testing "
                         "mode is on — receivers may ignore verification "
                         "failures. Remove t=y when the key is live.")
        return found

    # -- MX / MTA-STS / TLS-RPT --------------------------------------------
    def check_mx(self, domain):
        try:
            answers = [a for a in self.resolver.query(domain, TYPE_MX)
                       if a["type"] == TYPE_MX]
        except DNSError as exc:
            self.add("mx", "error", f"MX lookup failed: {exc}")
            return []
        if not answers:
            self.add("mx", "info",
                     "No MX records — mail to this domain falls back to "
                     "its A record. That is fine for a send-only domain; "
                     "add MX records if the domain should receive mail.")
        else:
            hosts = ", ".join(
                f"{a['exchange']} ({a['preference']})"
                for a in sorted(answers, key=lambda r: r["preference"]))
            self.add("mx", "ok", f"MX records present: {hosts}.")
        return answers

    def check_mta_sts(self, domain, fetch_policy=True):
        qname = f"_mta-sts.{domain}"
        try:
            texts = self.resolver.txt_records(qname)
        except DNSError:
            texts = []
        has_record = any(t.strip().lower().startswith("v=sts")
                         for t in texts)
        if not has_record:
            self.add("mta-sts", "info",
                     "No MTA-STS record — opportunistic TLS is not "
                     "enforced for this domain. Add one if you want "
                     "receivers to require encrypted delivery.")
            return
        self.add("mta-sts", "ok", "MTA-STS record present.")
        if not fetch_policy:
            return
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                policy = resp.read().decode("utf-8", "replace")
            mode = re.search(r"^mode:\s*(\S+)", policy, re.M)
            self.add("mta-sts", "ok",
                     "MTA-STS policy fetched: mode=" +
                     (mode.group(1) if mode else "unknown") + ".")
        except Exception:  # noqa: BLE001 - network is best-effort here
            self.add("mta-sts", "info",
                     "MTA-STS policy could not be fetched over HTTPS "
                     "(network or server unreachable) — the TXT record "
                     "itself is present.")

    def check_tls_rpt(self, domain):
        qname = f"_smtp._tls.{domain}"
        try:
            texts = self.resolver.txt_records(qname)
        except DNSError:
            texts = []
        has_record = any(t.strip().lower().startswith("v=tlsrpt")
                         for t in texts)
        if has_record:
            self.add("tls-rpt", "ok", "TLS-RPT record present.")
        else:
            self.add("tls-rpt", "info",
                     "No TLS-RPT record — you will not get reports about "
                     "TLS delivery failures for this domain.")

    def run(self, domain, fetch_policy=True):
        self.check_spf(domain)
        self.check_dmarc(domain)
        self.check_dkim(domain)
        self.check_mx(domain)
        self.check_mta_sts(domain, fetch_policy=fetch_policy)
        self.check_tls_rpt(domain)
        return self.findings


# --------------------------------------------------------------------------
# Fix plan
# --------------------------------------------------------------------------

def fix_plan(domain, findings, spf_parsed):
    """Exact records to publish, derived from the findings.

    Nothing is invented: provider-specific values (SPF includes, DKIM
    keys) are placeholders the user must fill from their provider.
    """
    lines = [f"# Fix plan for {domain}", ""]
    errors = [f for f in findings if f["level"] == "error"]
    warns = [f for f in findings if f["level"] == "warn"]
    if not errors and not warns:
        lines.append("Nothing to fix — SPF, DMARC and DKIM all pass.")
        return "\n".join(lines)
    spf_missing = any(f["check"] == "spf" and "No SPF record" in f["message"]
                      for f in errors)
    if spf_missing:
        lines += [
            "## 1. SPF — publish this TXT record at the domain root:",
            "",
            '    v=spf1 include:<your-provider> -all',
            "",
            "Replace <your-provider> with your mail provider's documented",
            "SPF include (see references/fix-playbook.md for the common",
            "ones). One include per provider that sends as this domain.",
            "",
        ]
    spf_plus_all = any(f["check"] == "spf" and "+all" in f["message"]
                       for f in errors)
    if spf_plus_all:
        lines += [
            "## 1. SPF — change +all to -all in the existing record.",
            "A record ending in +all authorises the whole internet.",
            "",
        ]
    spf_lookups = any(f["check"] == "spf" and "over the 10-lookup" in f["message"]
                      for f in errors)
    if spf_lookups:
        lines += [
            "## 1. SPF — too many DNS lookups.",
            "Remove or flatten include: mechanisms. Each include: costs",
            "one lookup, plus everything inside it. Ask providers that",
            "nest includes for a flattened record.",
            "",
        ]
    dmarc_missing = any(f["check"] == "dmarc" and "No DMARC record" in f["message"]
                        for f in errors)
    dmarc_none = any(f["check"] == "dmarc" and "p=none" in f["message"]
                     for f in warns)
    if dmarc_missing:
        lines += [
            "## 2. DMARC — publish this TXT record at _dmarc:",
            "",
            f'    v=DMARC1; p=none; rua=mailto:dmarc@{domain}',
            "",
            "Start at p=none (monitoring). Read the aggregate reports for",
            "a week, then move to p=quarantine, then p=reject.",
            "",
        ]
    elif dmarc_none:
        lines += [
            "## 2. DMARC — move from p=none to p=quarantine, then p=reject.",
            "Only after the aggregate reports show no legitimate mail is",
            "affected.",
            "",
        ]
    if not any(f["check"] == "dkim" and f["level"] == "ok" for f in findings):
        lines += [
            "## 3. DKIM — publish the key your mail provider gives you.",
            "",
            "Ask the provider for its DKIM selector and public key, then",
            "publish it as TXT <selector>._domainkey. The tool cannot",
            "invent a key — a DKIM key must be generated by the sender.",
            "",
        ]
    lines += [
        "## Then re-check:",
        "",
        f"    python3 mail_auth.py {domain} --recheck 12 --interval 300",
        "",
        "DNS changes take minutes to hours to propagate. The recheck loop",
        "re-runs the full check until it passes (or the attempts run out).",
        "",
        "Reminder: passing SPF/DKIM/DMARC is necessary, not sufficient,",
        "for inbox placement. Reputation, engagement and sending volume",
        "still decide whether mail lands in the inbox or in spam.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="mail_auth.py",
        description="Check a domain's email authentication "
                    "(SPF / DKIM / DMARC) and print the fix.")
    parser.add_argument("domain", help="domain to check, e.g. example.com")
    parser.add_argument("--resolver", default=None,
                        help="DNS server to ask (host or host:port); "
                             "default: the system's resolver")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds per DNS query (default 5)")
    parser.add_argument("--json", action="store_true",
                        help="print a machine-readable summary as JSON")
    parser.add_argument("--fix", action="store_true",
                        help="print the exact records to publish")
    parser.add_argument("--recheck", type=int, default=0,
                        help="repeat the check until it passes, up to N "
                             "attempts (DNS propagation wait)")
    parser.add_argument("--interval", type=int, default=300,
                        help="seconds between recheck attempts (default 300)")
    parser.add_argument("--strict", action="store_true",
                        help="also fail (exit 1) on warnings")
    parser.add_argument("--selectors", default=None,
                        help="comma-separated DKIM selectors to probe "
                             "(default: the built-in list of 15)")
    parser.add_argument("--no-mta-sts-policy", action="store_true",
                        help="do not try to fetch the MTA-STS policy "
                             "over HTTPS")
    return parser.parse_args(argv)


def summarize(findings):
    counts = {"error": 0, "warn": 0, "ok": 0, "info": 0}
    for finding in findings:
        counts[finding["level"]] = counts.get(finding["level"], 0) + 1
    return counts


def print_human(domain, findings):
    level_mark = {"error": "FAIL", "warn": "WARN", "ok": "OK", "info": "INFO"}
    print(f"mail-auth check for {domain}")
    print()
    for finding in findings:
        mark = level_mark[finding["level"]]
        print(f"[{mark}] {finding['check']}: {finding['message']}")
        if finding.get("detail"):
            print(f"       {finding['detail']}")
    counts = summarize(findings)
    print()
    print(f"{counts['error']} {'error' if counts['error'] == 1 else 'errors'}, "
          f"{counts['warn']} {'warning' if counts['warn'] == 1 else 'warnings'}, "
          f"{counts['ok']} passing, {counts['info']} informational.")


def main(argv=None):
    args = parse_args(argv)
    domain = args.domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        print("error: give a domain, e.g. example.com", file=sys.stderr)
        return 2
    stub_path = __import__("os").environ.get("MAIL_AUTH_DNS_STUB")
    if stub_path:
        resolver = Resolver([("stub", 0)], timeout=args.timeout,
                            transport=load_stub_transport(stub_path))
    elif args.resolver:
        if ":" in args.resolver:
            host, port = args.resolver.rsplit(":", 1)
            servers = [(host, int(port))]
        else:
            servers = [(args.resolver, 53)]
        resolver = Resolver(servers, timeout=args.timeout)
    else:
        resolver = Resolver.system(timeout=args.timeout)
    selectors = ([s.strip() for s in args.selectors.split(",") if s.strip()]
                 if args.selectors else None)
    fetch_policy = not args.no_mta_sts_policy

    # Pre-flight: one probe query. If the resolver does not answer at
    # all, that is a DNS failure (exit 2) — not "every record is
    # missing" (exit 1). The individual checks swallow DNSError on
    # purpose, so this probe is what separates the two cases.
    try:
        resolver.txt_records(domain)
    except DNSError as exc:
        print(f"error: DNS lookup failed: {exc}", file=sys.stderr)
        return 2

    attempts = max(1, args.recheck) if args.recheck else 1
    findings = []
    for attempt in range(attempts):
        checker = Checker(resolver, selectors=selectors)
        try:
            findings = checker.run(domain, fetch_policy=fetch_policy)
        except DNSError as exc:
            print(f"error: DNS lookup failed: {exc}", file=sys.stderr)
            return 2
        counts = summarize(findings)
        failed = counts["error"] > 0 or (args.strict and counts["warn"] > 0)
        if not failed or attempt == attempts - 1:
            break
        print(f"attempt {attempt + 1}/{attempts}: {counts['error']} errors — "
              f"waiting {args.interval}s for DNS propagation…")
        time.sleep(args.interval)

    if args.json:
        counts = summarize(findings)
        print(json.dumps({
            "domain": domain,
            "findings": findings,
            "counts": counts,
        }, indent=2))
    else:
        print_human(domain, findings)

    if args.fix:
        print()
        print(fix_plan(domain, findings, None))

    counts = summarize(findings)
    if counts["error"] > 0:
        return 1
    if args.strict and counts["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
