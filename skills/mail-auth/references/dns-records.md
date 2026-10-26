# DNS records for mail authentication

## SPF (Sender Policy Framework) — TXT at the domain root

```
v=spf1 include:_spf.google.com -all
```

Lists who may send mail as the domain. Receivers check the sending
server against it.

- **Missing** — anyone can forge mail from the domain. Error.
- **10-lookup limit (RFC 7208)** — evaluating SPF may cause at most 10
  DNS queries. `include:`, `a`, `mx`, `ptr` and `exists:` each cost one
  lookup, *plus* everything inside an included record. Over the limit,
  receivers stop and treat the result as a permanent error. This is the
  most common way a long-standing SPF record silently breaks: every new
  provider adds an include until the count tips over.
- **Void lookups** — a mechanism that resolves to nothing (e.g. an
  `include:` to a domain with no SPF). At most 2 are allowed.
- **`all` qualifier** — `-all` (fail: strict, what you want once all
  legitimate senders are covered), `~all` (softfail: accepted while
  testing), `?all` (neutral: useless), `+all` (pass: authorises the
  whole internet — a hole, worse than no SPF at all).

## DMARC — TXT at `_dmarc.<domain>`

```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

Tells receivers what to do with mail that fails SPF or DKIM
authentication (alignment required: the SPF/DKIM domain must match the
visible From domain).

- **Missing** — receivers have no instruction. Error.
- **`p=` policy** — `none` (monitor only, no action), `quarantine`
  (send failures to spam), `reject` (refuse failures). Roll out in
  that order; see `references/fix-playbook.md`.
- **`pct=`** — percentage of failing mail the policy applies to
  (default 100).
- **`rua=`** — where aggregate reports go. Without it you never see
  who fails or who abuses the domain.
- **`sp=`** — policy for subdomains (defaults to `p=`).

## DKIM (DomainKeys Identified Mail) — TXT at `<selector>._domainkey.<domain>`

```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
```

A cryptographic signature added by the sender; receivers verify it
against the published public key.

- **The key comes from the mail provider.** The provider generates the
  key pair, signs with the private key, and gives you the selector and
  public key to publish. A DKIM key you generate yourself is useless
  unless you also control the signing — never present a self-generated
  key as the provider's.
- **Key size** — under 1024 bits: weak, error. 1024 bits: works but
  dated, warning. 2048 bits: current recommendation.
- **`t=y`** — testing mode: receivers may ignore verification failures.
  Remove it when the key is live.
- **Selector probing** — the checker tries 15 common selectors
  (`default`, `google`, `mail`, `s1`, `selector1`, …). A provider can
  use any selector name; if none of the probed ones answer, the report
  says "no key found for the probed selectors" — check the provider's
  documentation for the real selector before concluding DKIM is absent.

## MX — mail exchangers

```
10 mx.example.com.
```

Where mail *to* the domain is delivered. Absence only means the domain
does not receive mail — a send-only domain (e.g. a marketing subdomain)
legitimately has none. That is why the checker reports it as
informational, never as an error.

## MTA-STS — TXT at `_mta-sts.<domain>` + policy over HTTPS

```
v=STSv1; id=20261027
```

Tells receivers to require encrypted (TLS) delivery, with the policy
fetched from `https://mta-sts.<domain>/.well-known/mta-sts.txt`
(`mode: enforce` / `mode: testing`, plus the MX hosts). Informational
in v1: the checker confirms the TXT record and fetches the policy
best-effort.

## TLS-RPT — TXT at `_smtp._tls.<domain>`

```
v=TLSRPTv1; rua=mailto:tls@example.com
```

Where receivers send reports about TLS delivery failures. Informational
in v1.

## The limit: authentication ≠ inbox placement

Passing SPF, DKIM and DMARC proves the mail is genuinely from the
domain. It does not prove Gmail (or anyone) will put it in the inbox.
Reputation (is the domain/IP known for spam?), engagement (do
recipients open and reply?), volume (sudden bulk sends?), and content
still decide placement. A domain can pass every check and still land in
spam — when the checker says "0 errors" and mail still goes to spam,
the problem is reputation or engagement, not authentication.
