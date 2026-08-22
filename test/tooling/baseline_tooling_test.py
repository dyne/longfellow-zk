#!/usr/bin/env python3
"""Schema and replay contract tests for reproducibility tooling."""
import csv
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
METRICS = ROOT / "scripts" / "baseline_metrics.py"
FIELDS = ["run", "circuit", "input_path", "input_bytes", "sha256", "resident_bytes"]


def metrics(path: Path) -> bytes:
    subprocess.run([sys.executable, str(METRICS), "--runs", "3", "--output", str(path)],
                   check=True, capture_output=True, text=True)
    return path.read_bytes()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="baseline-tooling-") as directory:
        first = Path(directory) / "first.csv"
        second = Path(directory) / "second.csv"
        assert metrics(first) == metrics(second), "three-run metric output drifted"
        with first.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
            assert stream.seek(0) == 0
            assert next(csv.reader(stream)) == FIELDS
        assert len(rows) == 12
        assert {row["circuit"] for row in rows} == {"synthetic", "bip340", "blindzap", "mdoc"}
        assert {row["run"] for row in rows} == {"1", "2", "3"}
        assert all(len(row["sha256"]) == 64 and int(row["input_bytes"]) > 0 for row in rows)
        warning = Path(directory) / "warning.cc"
        warning.write_text("int main() { int uninitialized; return uninitialized; }\n")
        result = subprocess.run([
            "clang-tidy", "-checks=clang-analyzer-core.uninitialized.*",
            "-warnings-as-errors=clang-analyzer-core.uninitialized.*", str(warning), "--", "-std=c++20",
        ], capture_output=True, text=True, check=False)
        assert result.returncode != 0 and "uninitialized" in (result.stdout + result.stderr)
    print("baseline tooling: CSV schema, three runs, and deterministic replay verified")


if __name__ == "__main__":
    main()
