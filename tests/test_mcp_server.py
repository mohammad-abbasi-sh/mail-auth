#!/usr/bin/env python3
"""End-to-end tests for mcp-server/mail_auth_mcp_server.py.

Spawns the server as a subprocess, speaks JSON-RPC over stdio, and
verifies initialize, tools/list, and real tools/call runs against the
stub DNS zone (via MAIL_AUTH_DNS_STUB, inherited by the server).
Standard library only.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "mcp-server" / "mail_auth_mcp_server.py"

GOOD_ZONE = {
    "example.test|16": [{"type": 16,
                         "text": "v=spf1 include:_spf.a.example.test mx -all"}],
    "_spf.a.example.test|16": [{"type": 16,
                                "text": "v=spf1 ip4:192.0.2.0/24 -all"}],
    "_dmarc.example.test|16": [{"type": 16,
                                "text": "v=DMARC1; p=reject; "
                                        "rua=mailto:dmarc@example.test"}],
    "example.test|15": [{"type": 15, "preference": 10,
                         "exchange": "mail.example.test"}],
}


class McpServerTest(unittest.TestCase):
    def spawn(self, extra_env=None):
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, cwd=str(ROOT), env=env)
        # Close stdin first (EOF ends the server's read loop), then wait.
        self.addCleanup(self._stop, proc)
        return proc

    @staticmethod
    def _stop(proc):
        try:
            proc.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        proc.wait(timeout=10)

    def call(self, proc, payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        return json.loads(line)

    def notify(self, proc, payload):
        # Notifications get no response — write only, never read.
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def init(self, proc):
        self.call(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05",
                       "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        self.notify(proc, {"jsonrpc": "2.0",
                           "method": "notifications/initialized"})

    def test_initialize_and_list(self):
        proc = self.spawn()
        init = self.call(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05",
                       "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "mail-auth")
        self.notify(proc, {"jsonrpc": "2.0",
                           "method": "notifications/initialized"})
        listing = self.call(proc, {"jsonrpc": "2.0", "id": 2,
                                   "method": "tools/list"})
        names = [t["name"] for t in listing["result"]["tools"]]
        self.assertEqual(names, ["mail_auth"])

    def test_call_good_domain(self):
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False,
                encoding="utf-8") as handle:
            json.dump(GOOD_ZONE, handle)
            zone_path = handle.name
        try:
            proc = self.spawn({"MAIL_AUTH_DNS_STUB": zone_path})
            self.init(proc)
            resp = self.call(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "mail_auth",
                           "arguments": {"domain": "example.test"}}})
            text = resp["result"]["content"][0]["text"]
            self.assertIn("mail_auth exit code: 0", text)
            self.assertIn("0 errors", text)
            self.assertIn("[OK] spf", text)
        finally:
            os.unlink(zone_path)

    def test_call_with_fix_includes_records(self):
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False,
                encoding="utf-8") as handle:
            json.dump({"broken.test|16": [{"type": 16,
                                           "text": "v=spf1 +all"}]},
                      handle)
            zone_path = handle.name
        try:
            proc = self.spawn({"MAIL_AUTH_DNS_STUB": zone_path})
            self.init(proc)
            resp = self.call(proc, {
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "mail_auth",
                           "arguments": {"domain": "broken.test",
                                         "fix": True}}})
            text = resp["result"]["content"][0]["text"]
            self.assertIn("mail_auth exit code: 1", text)
            # The JSON findings must survive alongside the fix plan.
            self.assertIn("[ERROR] spf", text)
            self.assertIn("# Fix plan for broken.test", text)
            self.assertIn("v=DMARC1; p=none", text)
        finally:
            os.unlink(zone_path)


if __name__ == "__main__":
    unittest.main()
