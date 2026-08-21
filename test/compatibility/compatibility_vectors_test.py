#!/usr/bin/env python3
"""Contract tests for checked-in compatibility vectors and failure names."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "compatibility_vectors.py"
REVIEWED = ROOT / "test" / "compatibility"


def run(directory: Path, implementation: str, expected: int = 0) -> str:
    result = subprocess.run([sys.executable, str(GENERATOR), "--directory", str(directory),
                             "--implementation", implementation], text=True,
                            capture_output=True, check=False)
    if result.returncode != expected:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="compatibility-test-") as temporary:
        copied = Path(temporary) / "vectors"
        shutil.copytree(REVIEWED, copied)
        run(copied, "cpp")
        run(copied, "rust")
        report = Path(temporary) / "rust-report.txt"
        result = subprocess.run([sys.executable, str(GENERATOR), "--directory", str(copied),
                                 "--write-rust-report", str(report)], text=True,
                                capture_output=True, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        report.write_text(report.read_text().replace("\t", "\t0", 1))
        result = subprocess.run([sys.executable, str(GENERATOR), "--directory", str(copied),
                                 "--rust-report", str(report)], text=True,
                                capture_output=True, check=False)
        assert result.returncode == 1 and "cpp↔rust:" in (result.stdout + result.stderr)
        vectors = copied / "vectors.json"
        data = json.loads(vectors.read_text())
        data["artifacts"][0]["sha256"] = "00" * 32
        vectors.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        # Recreate the manifest hash so this exercises named artifact failures,
        # rather than only the outer manifest integrity check.
        manifest = copied / "manifest.json"
        import hashlib
        value = json.loads(manifest.read_text())
        value["vectors_sha256"] = hashlib.sha256(vectors.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        for implementation in ("cpp", "rust"):
            output = run(copied, implementation, expected=1)
            assert f"{implementation}: transcript hash mismatch" in output, output
    print("compatibility vectors: deterministic and named drift failures verified")


if __name__ == "__main__":
    main()
