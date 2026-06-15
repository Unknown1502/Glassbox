import json
import unittest

from _util import ROOT  # noqa: F401
from glassbox import sift_adapters


class TestSiftAdapters(unittest.TestCase):
    """Exercise the live SIFT parsers with canned CLI output (no VM needed)."""

    def test_vol_pslist_json_parse(self):
        canned = json.dumps([
            {"PID": 4188, "PPID": 612, "ImageFileName": "upd.exe", "CreateTime": "2026-05-30T02:14:31"},
            {"PID": 612, "PPID": 488, "ImageFileName": "services.exe", "CreateTime": "2026-05-30T01:40:02"},
        ])
        out = sift_adapters.vol_pslist(lambda argv: canned, "vol", "mem.raw", {})
        self.assertEqual(len(out["processes"]), 2)
        self.assertEqual(out["processes"][0]["pid"], 4188)

    def test_vol_malfind_flags_rwx(self):
        canned = json.dumps([
            {"PID": 4188, "Process": "upd.exe", "Protection": "PAGE_EXECUTE_READWRITE",
             "Start VPN": "0x1d0000", "End VPN": "0x1d8000", "Disasm": "55 8b ec"},
        ])
        out = sift_adapters.vol_malfind(lambda argv: canned, "vol", "mem.raw", {})
        self.assertEqual(out["hits"][0]["pid"], 4188)
        self.assertIn("RWX private memory", out["hits"][0]["indicators"])

    def test_vol_netscan_flags_external_only(self):
        canned = json.dumps([
            {"PID": 4188, "Owner": "upd.exe", "Proto": "TCPv4", "LocalAddr": "10.4.12.51",
             "LocalPort": 49733, "ForeignAddr": "185.220.101.47", "ForeignPort": 443, "State": "ESTABLISHED"},
            {"PID": 2104, "Owner": "chrome.exe", "Proto": "TCPv4", "LocalAddr": "10.4.12.51",
             "LocalPort": 50112, "ForeignAddr": "10.4.12.9", "ForeignPort": 445, "State": "ESTABLISHED"},
        ])
        out = sift_adapters.vol_netscan(lambda argv: canned, "vol", "mem.raw", {})
        flagged = [c for c in out["connections"] if c["suspicious"]]
        self.assertEqual(len(flagged), 1)
        self.assertTrue(flagged[0]["foreign_addr"].startswith("185.220.101.47"))

    def test_yara_line_parse(self):
        canned = "Cobalt_Strike_Beacon /cases/evidence/upd.exe\n"
        out = sift_adapters.yara_scan(lambda argv: canned, "yara", "/cases/evidence",
                                      {"ruleset": "/rules/index.yar"})
        self.assertEqual(out["matches"][0]["rule"], "Cobalt_Strike_Beacon")

    def test_runkeys_parse_flags_programdata(self):
        canned = "Updater -> C:\\ProgramData\\upd.exe\nOneDrive -> C:\\Users\\j\\OneDrive.exe\n"
        out = sift_adapters.get_runkeys(lambda argv: canned, "rip.pl", "SOFTWARE", {})
        susp = [k for k in out["runkeys"] if k["suspicious"]]
        self.assertEqual(len(susp), 1)
        self.assertEqual(susp[0]["name"], "Updater")

    def test_parse_live_unsupported_raises(self):
        with self.assertRaises(NotImplementedError):
            sift_adapters.parse_live("get_amcache", "regripper", "ev", {}, lambda a: "")


if __name__ == "__main__":
    unittest.main()
