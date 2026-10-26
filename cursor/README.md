# Cursor — mail-auth rule

`cursor/mail-auth.mdc` is the Cursor version of this skill. It carries
the same contract in condensed form: check first with the tool, fix
with exact records (never invented provider values), prove the fix
with the re-check loop, and state the authentication ≠ inbox placement
limit.

## Install

Copy `cursor/mail-auth.mdc` into your project's `.cursor/rules/`
directory (create it if needed). Cursor applies it automatically. The
rule points at the checker script — copy the whole
`skills/mail-auth/` directory into your project, or install the
checker where the rule's commands can find it.

## What it covers

- The check-first contract (SPF / DKIM / DMARC / MX / MTA-STS /
  TLS-RPT).
- The fix rules (exact records, provider placeholders, staged DMARC
  rollout).
- The proof rule (re-check loop until exit 0).
- The limit (passing auth does not prove inbox placement).

The full skill with references and the MCP server lives in
`skills/mail-auth/` and `mcp-server/`.
