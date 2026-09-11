import json
import tempfile
import unittest
from pathlib import Path

from ccrh.cli import scan
from ccrh.inventory.scanner import inventory


class SmokeTest(unittest.TestCase):
    def test_scan_finds_rsa_and_xor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "challenge.py").write_text("n = 123\ne = 3  # RSA\nflag = data ^ key\n", encoding="utf-8")
            output = root / "report.json"
            self.assertEqual(scan(root, output, None), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(report["files"]), 1)
            self.assertEqual({item["kind"] for item in report["ranked_attacks"]}, {"rsa", "xor"})
            self.assertEqual({item["name"] for item in report["parameters"]}, {"n", "e"})

    def test_inventory_hashes_files_and_ignores_metadata_dirs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "visible.txt").write_text("hello", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "ignored").write_text("not challenge data", encoding="utf-8")
            records = inventory(root)
            self.assertEqual([record.path for record in records], ["visible.txt"])
            self.assertEqual(records[0].kind, "text")
            self.assertEqual(len(records[0].sha256), 64)


if __name__ == "__main__":
    unittest.main()
