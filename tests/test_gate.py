import unittest

from _util import ROOT  # noqa: F401
from glassbox.gate import apply_gate
from glassbox.schemas import Claim, Confidence, Verdict


class TestGate(unittest.TestCase):
    def test_unbound_claim_demoted_to_inference(self):
        c = Claim("the host is compromised", supporting_exec_ids=[],
                  proposed_confidence=Confidence.CONFIRMED)
        d = apply_gate(c, known_exec_ids=set())
        self.assertEqual(c.final_confidence, Confidence.INFERENCE)
        self.assertEqual(d.after, Confidence.INFERENCE)

    def test_refuted_claim_demoted(self):
        c = Claim("psexesvc is malware", supporting_exec_ids=["exec_1"],
                  proposed_confidence=Confidence.CONFIRMED,
                  skeptic_verdict=Verdict.REFUTE, skeptic_note="signed admin tool")
        apply_gate(c, known_exec_ids={"exec_1"})
        self.assertEqual(c.final_confidence, Confidence.INFERENCE)

    def test_confirmed_requires_binding_and_confirm(self):
        c = Claim("persistence via run key", supporting_exec_ids=["exec_1"],
                  proposed_confidence=Confidence.CONFIRMED,
                  skeptic_verdict=Verdict.CONFIRM)
        apply_gate(c, known_exec_ids={"exec_1"})
        self.assertEqual(c.final_confidence, Confidence.CONFIRMED)

    def test_pending_cannot_be_confirmed(self):
        c = Claim("x", supporting_exec_ids=["exec_1"],
                  proposed_confidence=Confidence.CONFIRMED,
                  skeptic_verdict=Verdict.PENDING)
        apply_gate(c, known_exec_ids={"exec_1"})
        self.assertNotEqual(c.final_confidence, Confidence.CONFIRMED)

    def test_unknown_exec_id_is_not_binding(self):
        c = Claim("x", supporting_exec_ids=["ghost"],
                  proposed_confidence=Confidence.CONFIRMED,
                  skeptic_verdict=Verdict.CONFIRM)
        apply_gate(c, known_exec_ids={"exec_1"})
        self.assertEqual(c.final_confidence, Confidence.INFERENCE)


if __name__ == "__main__":
    unittest.main()
