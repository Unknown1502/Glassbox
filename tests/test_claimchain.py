import os
import tempfile
import unittest

from _util import ROOT  # noqa: F401  (ensures sys.path)
from glassbox.claimchain import ClaimChain
from glassbox.schemas import ToolExecution, Claim, Confidence


class TestClaimChain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "ledger.jsonl")
        self.led = ClaimChain(self.path)

    def test_chain_intact_after_appends(self):
        self.led.record_event("hello", {"a": 1})
        ex = ToolExecution("get_runkeys", {}, "ev", "off", "deadbeef", "summary")
        self.led.record_exec(ex)
        self.led.record_claim(Claim("an assertion", supporting_exec_ids=[ex.tool_exec_id]))
        res = self.led.verify_chain()
        self.assertTrue(res["ok"])
        self.assertEqual(res["links"], 3)

    def test_tamper_is_detected(self):
        for i in range(4):
            self.led.record_event(f"e{i}", {"i": i})
        # Corrupt the body of line 2 without fixing its hash.
        lines = open(self.path, encoding="utf-8").read().splitlines()
        lines[2] = lines[2].replace('"i":2', '"i":999')
        open(self.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        res = ClaimChain(self.path).verify_chain()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 2)

    def test_export_reconstructs_state(self):
        ex = ToolExecution("get_amcache", {}, "ev", "off", "abc123", "sum")
        self.led.record_exec(ex)
        c = Claim("claim text", supporting_exec_ids=[ex.tool_exec_id],
                  proposed_confidence=Confidence.PROBABLE)
        self.led.record_claim(c)
        self.led.record_verdict(c.claim_id, "confirm", "ok", [ex.tool_exec_id])
        self.led.record_gate(c.claim_id, "probable", "confirmed", "bound + confirmed")
        data = self.led.export_report_data()
        self.assertIn(ex.tool_exec_id, data["executions"])
        self.assertEqual(data["claims"][c.claim_id]["final_confidence"], "confirmed")
        self.assertEqual(data["claims"][c.claim_id]["skeptic_verdict"], "confirm")


if __name__ == "__main__":
    unittest.main()
