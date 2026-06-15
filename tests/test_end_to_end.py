import os
import tempfile
import unittest

from _util import CASE_DIR
from glassbox.orchestrator import Orchestrator, RunConfig
from glassbox.schemas import Confidence, ClaimKind, Verdict


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = tempfile.mkdtemp()
        cfg = RunConfig(case_dir=CASE_DIR, out_dir=out, max_iterations=20)
        cls.result = Orchestrator(cfg).run()

    def test_artifacts_written(self):
        for p in (self.result.report_path, self.result.ledger_path,
                  self.result.certificate_path, self.result.accuracy_path):
            self.assertTrue(os.path.exists(p), p)

    def test_perfect_recall_and_no_hallucinations(self):
        s = self.result.summary
        self.assertEqual(s["recall"], 1.0)
        self.assertEqual(s["hallucinations"], 0)
        self.assertEqual(s["decoy_flagged"], 0)

    def test_self_correction_happened(self):
        # exactly one claim was refuted by the skeptic and demoted off "confirmed"
        refuted = [c for c in self.result.claims if c.skeptic_verdict == Verdict.REFUTE]
        self.assertGreaterEqual(len(refuted), 1)
        for c in refuted:
            self.assertNotEqual(c.final_confidence, Confidence.CONFIRMED)

    def test_a_hypothesis_was_killed(self):
        killed = [h for h in self.result.hypotheses if h.status == "killed"]
        self.assertGreaterEqual(len(killed), 1)

    def test_adversarial_ioc_reported(self):
        adv = [c for c in self.result.claims if c.kind == ClaimKind.ADVERSARIAL]
        self.assertGreaterEqual(len(adv), 1)
        self.assertEqual(adv[0].final_confidence, Confidence.CONFIRMED)

    def test_integrity_certificate_passes(self):
        self.assertTrue(self.result.certificate["overall_ok"])
        self.assertTrue(self.result.certificate["canaries_ok"])
        self.assertTrue(self.result.certificate["ledger_chain_ok"])

    def test_skeptic_is_independent_tooling(self):
        # every confirmed forensic claim was re-derived with a DIFFERENT tool
        data = __import__("glassbox.claimchain", fromlist=["ClaimChain"]) \
            .ClaimChain(self.result.ledger_path).export_report_data()
        execs = data["executions"]
        for c in self.result.claims:
            if c.kind != ClaimKind.FINDING or c.final_confidence != Confidence.CONFIRMED:
                continue
            inv_tools = {execs[e]["tool_name"] for e in c.supporting_exec_ids if e in execs}
            sk_tools = {execs[e]["tool_name"] for e in c.skeptic_exec_ids if e in execs}
            self.assertTrue(sk_tools, "skeptic produced no execution")
            self.assertTrue(inv_tools.isdisjoint(sk_tools),
                            f"skeptic reused investigator tool for: {c.assertion[:40]}")


if __name__ == "__main__":
    unittest.main()
