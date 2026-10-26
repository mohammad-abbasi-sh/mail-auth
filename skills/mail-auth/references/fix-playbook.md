# Fix playbook — from a failing check to passing mail

## 1. SPF

**Missing record.** Publish one TXT record at the domain root:

```
v=spf1 include:<your-provider> -all
```

One `include:` per provider that sends as the domain. Common
documented includes (verify against the provider's own docs before
publishing — providers change these):

| Provider | SPF include |
|---|---|
| Google Workspace / Gmail | `_spf.google.com` |
| Microsoft 365 / Outlook | `spf.protection.outlook.com` |
| Mailchimp (transactional/Mandrill) | `spf.mandrillapp.com` |
| SendGrid | `sendgrid.net` |
| Amazon SES | `amazonses.com` |
| Zoho Mail | `zoho.com` (or `zohomail.com` per Zoho docs) |

**Over the 10-lookup limit.** List the includes (the checker counts
them) and remove the ones no longer sending. Ask providers that nest
includes for a flattened record, or replace a chain of includes with
the providers' `ip4:` ranges. Never "fix" it by deleting SPF.

**`+all`.** Change it to `-all` once every legitimate sender is in the
record. While migrating, `~all` is the safe intermediate step.

## 2. DMARC — staged rollout, never straight to reject

| Step | Record at `_dmarc` | Wait |
|---|---|---|
| 1. Monitor | `v=DMARC1; p=none; rua=mailto:dmarc@<domain>` | Read aggregate reports for a week: which legitimate senders fail? Fix their SPF/DKIM first. |
| 2. Quarantine | `v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@<domain>` | Raise `pct` 25 → 50 → 100 over days. |
| 3. Reject | `v=DMARC1; p=reject; rua=mailto:dmarc@<domain>` | Final state. Keep `rua=` so abuse stays visible. |

Going straight to `p=reject` on day one is how legitimate mail gets
refused. The reports are the point of step 1 — do not skip it.

## 3. DKIM

1. In the mail provider's admin panel, enable DKIM signing. The
   provider generates the key pair and shows a selector (often
   `default`, `google`, `s1`…) and the public key.
2. Publish it as a TXT record at `<selector>._domainkey.<domain>`:
   `v=DKIM1; k=rsa; p=<public key>`.
3. Re-run the checker — the selector should now appear with its key
   size. Rotate keys by publishing a new selector and retiring the old
   one; never delete the old key before the new one verifies.

If the provider offers only 1024-bit keys, accept it (warning, not
error) and ask when 2048-bit rotation is available.

## 4. After publishing — the re-check loop

DNS changes take minutes to hours to propagate, and different resolvers
see the change at different times. Do not declare the fix done after
publishing:

```bash
python3 scripts/mail_auth.py <domain> --recheck 12 --interval 300
```

Twelve attempts, five minutes apart. When it exits 0, the fix is
proven — quote the final `0 errors` line. If it still fails after the
loop, the record was published wrong (typo, wrong host, missing quotes
in the provider panel) — re-read the published record with the checker
in `--json` mode and compare it character by character.

## 5. When auth passes and mail still goes to spam

That is the expected boundary of this skill. Check, in order:
Google Postmaster Tools (domain reputation, spam rate), sending volume
(a sudden bulk send from a cold domain), engagement (recipients
marking mail as spam), and content (URL shorteners, all-image mail,
misleading subject lines). None of those is a DNS problem, and no DNS
change will fix them.
