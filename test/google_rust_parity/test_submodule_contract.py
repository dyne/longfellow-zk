#!/usr/bin/env python3
"""Hermetic black-box tests for scripts/google_rust_parity.sh.

The tested copy only substitutes the fixture's local upstream URL; production
code retains its fixed Google URL and no test switch exists in the runner.
"""
from __future__ import annotations
import os, pathlib, shutil, subprocess, tempfile, unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/google_rust_parity.sh"

def run(args, cwd=None, **kwargs):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True, **kwargs)

class SubmoduleContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = pathlib.Path(self.temp.name)
        self.upstream = self.root / "upstream"; self.super = self.root / "super"
        run(["git", "init", self.upstream]); run(["git", "config", "user.email", "test@example.invalid"], self.upstream); run(["git", "config", "user.name", "Test"], self.upstream)
        (self.upstream / "README").write_text("fixture\n"); run(["git", "add", "README"], self.upstream); run(["git", "commit", "-m", "fixture"], self.upstream)
        run(["git", "init", self.super]); run(["git", "config", "user.email", "test@example.invalid"], self.super); run(["git", "config", "user.name", "Test"], self.super)
        run(["git", "-c", "protocol.file.allow=always", "submodule", "add", str(self.upstream), "vendor/longfellow-zk"], self.super)
        run(["git", "commit", "-am", "add submodule"], self.super)
        scripts = self.super / "scripts"; scripts.mkdir(); self.runner = scripts / "google_rust_parity.sh"
        self.runner.write_text(SCRIPT.read_text().replace("https://github.com/google/longfellow-zk", str(self.upstream)))
        self.runner.chmod(0o755)
        self.bin = self.root / "bin"; self.bin.mkdir()
        for name in ("cargo", "cmake", "python3"):
            shim = self.bin / name; shim.write_text("#!/bin/sh\nexit 0\n"); shim.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin"}
    def tearDown(self): self.temp.cleanup()
    def invoke(self): return subprocess.run(["/bin/bash", str(self.runner)], cwd=self.super, text=True, capture_output=True, env=self.env)
    def test_initialized_success(self):
        result = self.invoke(); self.assertEqual(result.returncode, 0); self.assertIn("google commit", result.stdout)
    def test_absent_checkout_bootstraps(self):
        run(["git", "submodule", "deinit", "-f", "--", "vendor/longfellow-zk"], self.super)
        result = self.invoke(); self.assertEqual(result.returncode, 0); self.assertTrue((self.super / "vendor/longfellow-zk/.git").exists())
    def test_wrong_revision_is_unchanged(self):
        (self.upstream / "README").write_text("new revision\n"); run(["git", "commit", "-am", "new revision"], self.upstream)
        newer = run(["git", "rev-parse", "HEAD"], self.upstream).stdout.strip()
        run(["git", "-C", "vendor/longfellow-zk", "fetch", "origin"], self.super); run(["git", "-C", "vendor/longfellow-zk", "checkout", "-q", newer], self.super)
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertIn("expected", result.stderr)
    def test_wrong_remote_is_unchanged(self):
        run(["git", "-C", "vendor/longfellow-zk", "remote", "set-url", "origin", "file:///wrong"], self.super)
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertIn("origin", result.stderr)
    def test_dirty_is_unchanged(self):
        target = self.super / "vendor/longfellow-zk/README"; target.write_text("dirty\n")
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertIn("dirty", result.stderr); self.assertEqual(target.read_text(), "dirty\n")
    def test_missing_git_and_clone_failure(self):
        no_git = {**self.env, "PATH": str(self.bin)}; result = subprocess.run(["/bin/bash", str(self.runner)], cwd=self.super, text=True, capture_output=True, env=no_git)
        self.assertNotEqual(result.returncode, 0); self.assertIn("Git", result.stderr)
        run(["git", "submodule", "deinit", "-f", "--", "vendor/longfellow-zk"], self.super)
        shutil.rmtree(self.super / ".git/modules/vendor/longfellow-zk"); shutil.rmtree(self.upstream)
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertIn("could not initialize", result.stderr)

if __name__ == "__main__": unittest.main()
