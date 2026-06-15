import unittest

from _util import ROOT  # noqa: F401
from glassbox.agent import _extract_json, _tool_catalog


class TestAgentJSON(unittest.TestCase):
    """The agent must survive messy LLM output (prose, fences, trailing text)."""

    def test_plain_json(self):
        self.assertEqual(_extract_json('{"action":"conclude","claims":[]}')["action"], "conclude")

    def test_fenced_json(self):
        s = "```json\n{\"action\":\"call_tool\",\"tool\":\"vol_pslist\"}\n```"
        self.assertEqual(_extract_json(s)["tool"], "vol_pslist")

    def test_json_with_prose(self):
        s = 'Sure, here is my next step:\n{"action":"call_tool","tool":"get_runkeys","args":{}}\nThanks!'
        out = _extract_json(s)
        self.assertEqual(out["tool"], "get_runkeys")

    def test_nested_object(self):
        s = '{"action":"call_tool","tool":"get_usn","args":{"name_filter":"evtx"}}'
        self.assertEqual(_extract_json(s)["args"]["name_filter"], "evtx")

    def test_garbage_returns_none(self):
        self.assertIsNone(_extract_json("no json here at all"))
        self.assertIsNone(_extract_json(""))

    def test_catalog_lists_only_readonly_tools(self):
        cat = _tool_catalog()
        self.assertIn("vol_malfind", cat)
        self.assertNotIn("execute_shell", cat)
        self.assertNotIn("write_file", cat)


if __name__ == "__main__":
    unittest.main()
