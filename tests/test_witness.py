import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "witness"))
import witness as w

PY = os.path.basename(sys.executable)

class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        open(os.path.join(self.d, "a.py"), "w").write("print(1)\n")
    def test_redacts_secrets_and_ids(self):
        s = "key AKIAABCDEFGHIJKLMNOP mail me@x.com PAN ABCDE1234F ph 9876543210 TOKEN=abc123 /home/priya/x"
        out, hit = w.redact(s)
        for bad in ("AKIAABCDEFGHIJKLMNOP", "me@x.com", "ABCDE1234F", "9876543210", "abc123", "priya"):
            self.assertNotIn(bad, out)
        self.assertTrue({"aws-key", "email", "pan", "phone", "secret-assign", "home-path"} <= set(hit))
    def test_redacts_windows_home(self):
        out, hit = w.redact(r"File C:\Users\hp\AppData\x.py failed")
        self.assertNotIn("hp", out); self.assertIn("home-path", hit)
    def test_home_path_in_command_not_refused_but_redacted_in_chat(self):
        cmd = r"C:\Users\hp\python.exe a.py"
        r = {"id": "x", "claim": "c", "command": cmd, "exit_code": 0, "seconds": 0.1, "tree": "t", "output_tail": ""}
        self.assertNotIn("hp", w.to_chat(r))
        p = w._parse_chat(w.to_chat(r))
        self.assertEqual(w.verify_receipt(p, self.d)[0], "UNCHECKABLE")
    def test_redacts_doubled_backslash_paths(self):
        out, hit = w.redact("name='C:\\\\Users\\\\hp\\\\AppData\\\\x.py' and C:\\Users\\hp\\y")
        self.assertNotIn("hp", out); self.assertIn("home-path", hit)
    def test_line_endings_do_not_cause_stale(self):
        d2 = tempfile.mkdtemp()
        open(os.path.join(d2, "a.py"), "wb").write(b"print(1)\r\n")
        open(os.path.join(self.d, "a.py"), "wb").write(b"print(1)\n")
        self.assertEqual(w.fingerprint(self.d), w.fingerprint(d2))
    def test_stale_names_the_differing_file(self):
        r = w.make_receipt(PY + " a.py", "prints", self.d)
        open(os.path.join(self.d, "b.py"), "wb").write(b"x = 1\n")
        verdict, why = w.verify_receipt(r, self.d)
        self.assertEqual(verdict, "STALE"); self.assertIn("b.py", " ".join(why))
    def test_holds(self):
        r = w.make_receipt(PY + " a.py", "prints", self.d)
        self.assertEqual(w.verify_receipt(r, self.d)[0], "HOLDS")
    def test_stale_after_edit(self):
        r = w.make_receipt(PY + " a.py", "prints", self.d)
        open(os.path.join(self.d, "a.py"), "a").write("print(2)\n")
        self.assertEqual(w.verify_receipt(r, self.d)[0], "STALE")
    def test_false_claim_caught(self):
        r = w.make_receipt(PY + " a.py", "prints", self.d)
        r["exit_code"] = 1
        self.assertEqual(w.verify_receipt(r, self.d)[0], "FALSE")
    def test_secret_in_command_refused(self):
        with self.assertRaises(SystemExit):
            w.make_receipt("curl -H 'Authorization: Bearer abcdefghijklmnop12345' x", "c", self.d)
    def test_chat_roundtrip(self):
        r = w.make_receipt(PY + " a.py", "prints", self.d)
        p = w._parse_chat(w.to_chat(r))
        self.assertEqual((p["tree"], p["command"], p["exit_code"]), (r["tree"], r["command"], r["exit_code"]))
        self.assertEqual(w.verify_receipt(p, self.d)[0], "HOLDS")
if __name__ == "__main__": unittest.main()
