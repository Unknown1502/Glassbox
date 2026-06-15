import os
import tempfile
import unittest

from _util import CASE_DIR
from glassbox.claimchain import ClaimChain
from glassbox.tools import ForensicTools, ToolError


class TestReadOnlySurface(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.led = ClaimChain(os.path.join(self.tmp, "l.jsonl"))
        self.tools = ForensicTools(CASE_DIR, self.led)

    def test_no_write_or_shell_tool_exists(self):
        surface = self.tools.available_tools()
        for forbidden in ("execute_shell", "shell", "write_file", "write",
                          "delete", "rm", "os_system", "run"):
            self.assertNotIn(forbidden, surface)

    def test_calling_a_shell_tool_is_refused(self):
        with self.assertRaises(ToolError):
            self.tools.call("execute_shell", cmd="rm -rf /")
        with self.assertRaises(ToolError):
            self.tools.call("write_file", path="x", data="y")

    def test_injection_in_args_is_rejected(self):
        with self.assertRaises(ToolError):
            self.tools.call("get_runkeys", path="SOFTWARE; rm -rf /")
        with self.assertRaises(ToolError):
            self.tools.call("yara_scan", path="$(reboot)")

    def test_forensic_paths_are_allowed(self):
        # $MFT, $UsnJrnl:$J etc. must pass validation.
        res = self.tools.get_mft_timeline(path="$MFT")
        self.assertIn("tool_exec_id", res)
        res2 = self.tools.get_usn(path="$Extend/$UsnJrnl:$J")
        self.assertIn("tool_exec_id", res2)

    def test_every_call_is_provenance_bound(self):
        res = self.tools.get_runkeys()
        self.assertIn("tool_exec_id", res)
        self.assertIn("raw_sha256", res)
        self.assertTrue(len(res["raw_sha256"]) == 64)
        data = self.led.export_report_data()
        self.assertIn(res["tool_exec_id"], data["executions"])


if __name__ == "__main__":
    unittest.main()
