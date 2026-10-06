"""Real C handler, fake maps: transport/security semantics only, never real denial."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from monitor.response import ControlClient, request_bytes

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"), "Linux C protocol test")
class ControlTests(unittest.TestCase):
    def test_identity_scope_idempotency_expiry_revoke_and_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            binary, endpoint, obj = temp/"server", temp/"control.sock", temp/"object"
            obj.write_text("harmless")
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-I"+str(ROOT/"bpf"),
                            str(ROOT/"tests/fixtures/control_mock.c"), "-o", str(binary)], check=True, capture_output=True)
            process = subprocess.Popen([str(binary), str(endpoint), str(obj)], stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+3
                while not endpoint.exists():
                    self.assertIsNone(process.poll())
                    if time.monotonic()>deadline: self.fail("mock endpoint timeout")
                    time.sleep(0.01)
                client=ControlClient(str(endpoint))
                req=dict(verb="APPLY", request_id="one", session_id="test-session", rule_version=1,
                         evidence_id="evidence", tgid=42, start_ns=100, exec_token=900,
                         uid=1000, object_id=1, ttl_ms=200)
                first=client.exchange(req)
                self.assertEqual(first["state"], "applied")
                self.assertLessEqual(first["update_before_ns"],first["update_after_ns"])
                self.assertEqual(client.exchange(req)["policy_id"], first["policy_id"])
                self.assertEqual(client.exchange({**req,"ttl_ms":201})["state"], "rejected")
                self.assertEqual(client.exchange({**req,"request_id":"two","exec_token":999})["state"], "rejected")
                self.assertEqual(client.exchange({**req,"request_id":"two"})["reason"], "request_id_conflict")
                self.assertEqual(client.exchange({**req,"request_id":"two","exec_token":999,"verb":"QUERY"})["reason"], "execution_identity")
                self.assertEqual(client.exchange({**req,"request_id":"wrong-session","session_id":"old"})["state"], "rejected")
                time.sleep(0.22)
                self.assertEqual(client.exchange({**req,"verb":"QUERY"})["state"], "expired")
                self.assertEqual(client.exchange(req)["state"], "expired")
                req={**req,"request_id":"next","ttl_ms":3000}
                self.assertEqual(client.exchange(req)["state"], "applied")
                self.assertEqual(client.exchange({**req,"verb":"REVOKE"})["state"], "revoked")
                obj.unlink(); obj.write_text("replacement")
                self.assertEqual(client.exchange({**req,"request_id":"replacement"})["reason"], "object_replaced")
                # Numeric signs, overflow and extra tokens must fail before sscanf conversion.
                for payload in (request_bytes(req)+b" extra", request_bytes(req).replace(b" 42 ",b" -42 "),
                                request_bytes(req).replace(b" 42 ",b" 18446744073709551616 ")):
                    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
                        peer.settimeout(1); peer.connect(str(endpoint)); peer.sendall(payload)
                        self.assertEqual(json.loads(peer.recv(1024))["state"], "rejected")
            finally:
                process.terminate(); process.wait(timeout=3)
