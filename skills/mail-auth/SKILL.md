---
name: mail-auth
description: Check a domain's email authentication (SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT) with a deterministic zero-dependency checker, print the exact DNS records to publish, and re-check until propagation completes. Use when mail "goes to spam", "never arrives", "fails authentication", when a domain moves to a new host or mail provider, or when onboarding a local business whose mail setup was never checked. Also use to verify a fix before reporting mail as fixed.
---

# Mail authentication — check it, fix it, prove it

Mail that lands in spam is usually a deterministic DNS problem, not a
mystery: a missing SPF record, a DMARC policy of `none`, a DKIM key
that was never published. This skill checks the records, prints the
exact fix, and re-checks until the fix has propagated.

## The contract

1. **Check first, with the tool — never guess.** Run the bundled checker
   (zero-dependency, pure stdlib, own DNS client — no `dnspython`, no
   `dig` subprocess):

   ```bash
   python3 scripts/mail_auth.py <domain> [--json] [--fix]
   ```

   It reports SPF (lookup count vs the 10-lookup limit, `+all` holes),
   DMARC (policy, `pct`, reporting address), DKIM (selector probing,
   key size), MX, MTA-STS and TLS-RPT. Exit codes: `0` = no errors ·
   `1` = errors found · `2` = the resolver did not answer.

2. **The fix is exact records, not advice.** With `--fix` the tool
   prints the TXT records to publish. Provider-specific values are
   placeholders — an SPF include and a DKIM key can only come from the
   mail provider that sends the mail. Never invent them, never copy a
   key from another domain, never publish a DKIM key you generated
   yourself and call it the provider's. See
   `references/fix-playbook.md` for the common provider includes and
   the staged DMARC rollout (none → quarantine → reject).

3. **Prove the fix with a re-check loop.** DNS takes minutes to hours
   to propagate. Do not report mail as fixed after publishing records —
   re-run the check until it passes:

   ```bash
   python3 scripts/mail_auth.py <domain> --recheck 12 --interval 300
   ```

   The loop re-runs the full check (up to 12 attempts, 5 minutes
   apart) until it exits 0. Quote the final `0 errors` line in your
   report.

4. **Know the limit — and say it.** Passing SPF, DKIM and DMARC is
   necessary, not sufficient, for inbox placement. Reputation,
   engagement, sending volume and content still decide whether Gmail
   delivers to the inbox or to spam. The checker proves authentication;
   it does not prove deliverability. Say so in every report (see
   `references/dns-records.md`).

## What each check means

- **SPF** — who may send as this domain. Missing = anyone can forge
  it. Over 10 DNS lookups = receivers stop evaluating (permanent
  error). `+all` = the whole internet is authorised.
- **DMARC** — what receivers do with mail that fails SPF/DKIM.
  `p=none` only watches; `p=quarantine` then `p=reject` enforce.
  No `rua=` = you never see the reports.
- **DKIM** — a cryptographic signature from the sender. The key must
  come from the mail provider; under 1024 bits is weak, 2048 bits is
  the recommendation.
- **MX** — where mail to the domain is delivered. Absence is only
  informational: a send-only domain legitimately has no MX.
- **MTA-STS / TLS-RPT** — opportunistic TLS enforcement and failure
  reporting. Informational in v1.

## When NOT to use this skill

- The problem is content, reputation or volume (bulk mail flagged
  despite passing auth) — the checker will say auth passes, and that
  *is* the answer: the problem is elsewhere.
- The domain's DNS is managed somewhere you cannot change — then the
  output is a report for the person who can, not a fix.
- You need inbox placement testing (seed lists, Gmail Postmaster data)
  — that is a different tool; this skill checks authentication only.
