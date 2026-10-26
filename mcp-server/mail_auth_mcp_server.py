#!/usr/bin/env python3
"""MCP server for mail-auth — expose the mail authentication checker
as a tool.

Zero-dependency (Python standard library only). Speaks JSON-RPC 2.0
over stdio, newline-delimited, following the MCP lifecycle:

    initialize -> notifications/initialized -> tools/list -> tools/call

Tool:
    mail_auth
        domain    domain to check (required)
        resolver  DNS server to ask (host or host:port)
        timeout   seconds per DNS query (default 5)
        strict    also fail on warnings (bool)
        fix       include the fix plan (exact records to publish) (bool)

The tool runs skills/mail-auth/scripts/mail_auth.py as a subprocess
with --json and returns its summary plus the fix plan when asked.
Exit-code semantics are preserved in the returned text (0 = no errors,
1 = errors found, 2 = the resolver did not answer).
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE.parent / "skills" / "mail-auth" / "scripts" / "mail_auth.py"

SERVER_INFO = {"name": "mail-auth", "version": "0.1.0"}
PROTOCOL_VERSION = "2024-11-05"


def run_checker(args):
    domain = args.get("domain")
    if not domain:
        raise ValueError("mail_auth requires 'domain'")
    cmd = [sys.executable, str(CHECKER), domain, "--json"]
    if args.get("resolver"):
        cmd += ["--resolver", str(args["resolver"])]
    cmd += ["--timeout", str(args.get("timeout", 5))]
    if args.get("strict"):
        cmd.append("--strict")
    if args.get("fix"):
        cmd.append("--fix")
    cmd += ["--no-mta-sts-policy"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    lines = [f"mail_auth exit code: {proc.returncode}"]
    # With --fix the CLI prints JSON followed by the fix plan; split
    # them before parsing, or the JSON parse fails and the findings
    # are lost.
    stdout = proc.stdout
    fix_text = ""
    if "\n# Fix plan" in stdout:
        stdout, fix_text = stdout.split("\n# Fix plan", 1)
        fix_text = "\n# Fix plan" + fix_text
    try:
        summary = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        summary = {}
    if summary:
        counts = summary.get("counts", {})
        lines.append(
            f"{counts.get('error', '?')} errors, "
            f"{counts.get('warn', '?')} warnings, "
            f"{counts.get('ok', '?')} passing.")
        for finding in summary.get("findings", []):
            lines.append(
                f"[{finding['level'].upper()}] {finding['check']}: "
                f"{finding['message']}")
            if finding.get("detail"):
                lines.append(f"    {finding['detail']}")
    if args.get("fix") and fix_text:
        lines.append(fix_text)
    if proc.stderr.strip():
        lines.append("stderr:")
        lines.append(proc.stderr.strip())
    return "\n".join(lines)


TOOLS = [
    {
        "name": "mail_auth",
        "description": (
            "Check a domain's email authentication (SPF, DKIM, DMARC, "
            "MX, MTA-STS, TLS-RPT) and return the findings plus, on "
            "request, the exact DNS records to publish. Returns the "
            "failure count and the fix plan. Passing authentication is "
            "necessary, not sufficient, for inbox placement."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "domain to check, e.g. example.com",
                },
                "resolver": {
                    "type": "string",
                    "description": "DNS server to ask (host or host:port)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "seconds per DNS query (default 5)",
                },
                "strict": {
                    "type": "boolean",
                    "description": "also fail on warnings",
                },
                "fix": {
                    "type": "boolean",
                    "description": "include the fix plan (records to publish)",
                },
            },
            "required": ["domain"],
        },
    }
]


def handle(request):
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {"tools": TOOLS},
        }
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name != "mail_auth":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32602,
                          "message": f"unknown tool: {name}"},
            }
        try:
            text = run_checker(arguments)
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }
        except Exception as exc:  # noqa: BLE001 - surface as tool error
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text",
                                        "text": f"error: {exc}"}],
                           "isError": True},
            }
    return {
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
