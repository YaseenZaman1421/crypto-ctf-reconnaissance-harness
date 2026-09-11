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
            self.assertEqual({item["name"] for item in report["parameters"]}, {"n", "e", "flag"})

    def test_solver_finds_exact_low_exponent_rsa_root_and_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "challenge.py").write_text("e = 3\nc = 10077696\nmessage = '68656c6c6f'\n", encoding="utf-8")
            output = root / "nested" / "report.json"
            self.assertEqual(scan(root, output, None), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            titles = {item["title"] for item in report["findings"]}
            self.assertIn("Exact low-exponent RSA root found", titles)
            self.assertIn("Printable hex layer detected", titles)

    def test_solver_finds_single_byte_xor_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = b"flag{bounded_xor}"
            ciphertext = bytes(byte ^ 0x2A for byte in plaintext).hex()
            (root / "challenge.py").write_text(f"ciphertext = '{ciphertext}'\n", encoding="utf-8")
            output = root / "report.json"
            scan(root, output, None)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("Printable single-byte XOR candidate", {item["title"] for item in report["findings"]})

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
