# mail-auth

**Check it, fix it, prove it.** An Agent Skill + deterministic checker
for a domain's email authentication — SPF, DKIM, DMARC, MX, MTA-STS,
TLS-RPT — that prints the exact DNS records to publish and re-checks
until propagation completes.

## The problem

Mail that lands in spam is usually a deterministic DNS problem, not a
mystery: a missing SPF record, a DMARC policy of `none`, a DKIM key
that was never published. The usual failure mode is worse than the
bug — someone publishes a record, waits an hour, and declares mail
fixed without ever re-checking. DNS takes minutes to hours to
propagate; the fix is only proven when the check passes *after* the
change.

## Quick start

```bash
# Check a domain
python3 skills/mail-auth/scripts/mail_auth.py example.com

# Check + print the exact records to publish
python3 skills/mail-auth/scripts/mail_auth.py example.com --fix

# Publish the records, then prove the fix (12 attempts, 5 min apart)
python3 skills/mail-auth/scripts/mail_auth.py example.com --recheck 12 --interval 300
```

Example output (against the test fixture zone in `tests/`):

```
mail-auth check for broken.test

[OK] spf: SPF record present (0 DNS lookups).
[FAIL] spf: SPF ends in +all — it authorises the whole internet to send as this domain.
[FAIL] dmarc: No DMARC record found.
[WARN] dkim: No DKIM key found for any probed selector (default, google, mail, mailchimp, mandrill, …).
[INFO] mx: No MX records — mail to this domain falls back to its A record.
[INFO] mta-sts: No MTA-STS record — opportunistic TLS is not enforced for this domain.
[INFO] tls-rpt: No TLS-RPT record — you will not get reports about TLS delivery failures.

2 errors, 1 warning, 1 passing, 3 informational.

# Fix plan for broken.test
## 1. SPF — change +all to -all in the existing record.
## 2. DMARC — publish this TXT record at _dmarc:
    v=DMARC1; p=none; rua=mailto:dmarc@broken.test
## 3. DKIM — publish the key your mail provider gives you.
```

Exit codes: `0` = no errors · `1` = errors found · `2` = the DNS
resolver did not answer at all.

## What it checks

| Check | What fails |
|---|---|
| SPF | Missing record; over the 10-lookup limit (includes counted recursively); `+all` authorising the internet; void lookups over 2 |
| DMARC | Missing record; `p=none` (monitoring only); missing `rua=` reporting address |
| DKIM | 15 selectors probed; keys under 1024 bits; `t=y` testing mode left on |
| MX | Informational only — a send-only domain legitimately has none |
| MTA-STS / TLS-RPT | Informational in v1 |

The checker has its own DNS client (pure Python stdlib over UDP — no
`dnspython`, no `dig` subprocess), so it works anywhere Python runs.
The test suite answers DNS from a stub transport, no network needed.

## The contract

1. **Check first, never guess.** The tool measures the SPF lookup
   count the way receivers do (recursive includes included).
2. **The fix is exact records.** Provider values are placeholders —
   an SPF include and a DKIM key can only come from the mail provider.
   The tool never invents them.
3. **Prove the fix.** `--recheck` re-runs the full check until it
   exits 0. Quote the final `0 errors` line.
4. **Know the limit.** Passing SPF, DKIM and DMARC is necessary, not
   sufficient, for inbox placement. Reputation, engagement and volume
   still decide whether Gmail delivers to the inbox or to spam. The
   checker proves authentication; it does not prove deliverability.

## How this differs from existing mail checkers

CLIs already exist (`dnsaudit` in Go, `vamp-mail-audit` on PyPI with
15-selector DKIM probing, `Invoke-SpfDkimDmarc` in PowerShell) — so
the checker alone would be a re-skin. The gap is *skill-shaped*: an
agent onboarding a business needs the deterministic DNS evidence
*plus* the exact records to publish *plus* a re-check loop until
propagation, as a Claude/Cursor skill with tests and an MCP tool. None
of the CLIs ships that.

## Install

- **Claude Code / Claude.ai:** copy `skills/mail-auth/` into your
  skills directory, or use the zip in `dist/` (extract it there).
- **Cursor:** copy `cursor/mail-auth.mdc` into `.cursor/rules/`
  (see `cursor/README.md`).
- **MCP:** `mcp-server/mail_auth_mcp_server.py` is a zero-dependency
  stdio MCP server exposing one tool, `mail_auth` (see `mcp-server/`).

## Tests

```bash
python3 -m unittest discover -s tests
```

22 checker tests (record parsers, a hand-built compressed DNS
response, fake-DNS end-to-end checks incl. the 10-lookup limit and
recursive includes, dead-resolver handling, the re-check loop) and 3
MCP server end-to-end tests — all passing.

## Layout

```
skills/mail-auth/
  SKILL.md                     the skill: the contract
  scripts/mail_auth.py         the checker (stdlib only, own DNS client)
  references/dns-records.md    what each record means + the auth ≠ inbox limit
  references/fix-playbook.md   staged DMARC rollout + provider SPF includes
cursor/mail-auth.mdc           Cursor rule (condensed contract)
mcp-server/mail_auth_mcp_server.py  MCP server (one tool: mail_auth)
tests/                         checker + MCP tests, stub DNS transport
dist/mail-auth-skill.zip       packaged skill
```

## License

MIT — see `LICENSE`.
