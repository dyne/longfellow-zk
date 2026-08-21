#!/usr/bin/env python3
"""Contract tests for checked-in compatibility vectors and failure names."""
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
        overlay = Path(temporary) / "source-only-overlay" / "src" / "proto"
        overlay.mkdir(parents=True)
        (overlay / "circuit_reader.h").write_text("// source-only parser change\n")
        result = subprocess.run([sys.executable, str(GENERATOR), "--directory", str(copied),
                                 "--include-root", str(overlay.parents[1])], text=True,
                                capture_output=True, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
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
        fixture = copied / "lfc1_fixture.bin"
        corrupted = bytearray(fixture.read_bytes())
        corrupted[0] ^= 1
        fixture.write_bytes(corrupted)
        for implementation in ("cpp", "rust"):
            output = run(copied, implementation, expected=1)
            assert f"{implementation}: lfc1 serialized byte drift" in output, output
    print("compatibility vectors: deterministic LFC1 and named drift failures verified")


if __name__ == "__main__":
    main()
