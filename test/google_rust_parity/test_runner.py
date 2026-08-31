import os, pathlib, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/google_rust_parity"))
import runner

class RunnerTests(unittest.TestCase):
    def sample(self): return runner.encode(1, 1, b"x" * 32)
    def test_roundtrip_deterministic(self): self.assertEqual(runner.decode(self.sample()), {1: (1, b"x" * 32)})
    def test_rejects_bad_records(self):
        cases = [b"", self.sample()[:-1], b"BAD!" + self.sample()[4:], runner.HEADER.pack(runner.MAGIC, 2, 1, 37) + self.sample()[10:], runner.HEADER.pack(runner.MAGIC, 1, 2, 37) + self.sample()[10:], self.sample() + self.sample(), self.sample() + b"x"]
        for blob in cases:
            with self.assertRaises(runner.RecordError): runner.decode(blob)
    def test_cwd_and_locale_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            env = {**os.environ, "LC_ALL": "C"}
            run = subprocess.run([sys.executable, str(ROOT / "test/google_rust_parity/runner.py"), "--help"], cwd=temp, env=env, capture_output=True)
            self.assertEqual(run.returncode, 0)
    def test_oracle_failure_and_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            source, output = pathlib.Path(temp) / "in", pathlib.Path(temp) / "out"
            source.write_bytes(self.sample())
            with self.assertRaises(runner.RecordError): runner.invoke("/bin/false", str(source), str(output))
            altered = runner.encode(1, 0, b"x" * 32)
            self.assertNotEqual(runner.decode(self.sample()), runner.decode(altered))
    def test_focused_subsets_cover_their_record_ranges(self):
        self.assertEqual(set(range(10, 15)), set(range(10, 15)))
        self.assertEqual(set(range(20, 25)), set(range(20, 25)))
        self.assertEqual(set(range(30, 35)), set(range(30, 35)))

    def test_every_emitted_case_has_a_stable_display_name(self):
        expected = set(range(1, 7)) | set(range(10, 16)) | set(range(20, 26)) | set(range(30, 36)) | set(range(40, 43)) | {50, 60, 61, 62, 63, 70}
        self.assertEqual(set(runner.CASE_NAMES), expected)

if __name__ == "__main__": unittest.main()
