#!/usr/bin/env python3
"""Contract test for the portable production-qualification matrix."""
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "qualification_matrix.py"
EXPECTED = [
    "cpp20-contract", "compatibility-lfc1", "lfc2-cross-language",
    "parser-transcript-fuzz", "ecdsa-dense-boundaries",
    "ownership-boundaries", "metric-schema",
]


def main() -> None:
    result = subprocess.run([sys.executable, str(SCRIPT), "--plan"], cwd=ROOT,
                            text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == EXPECTED
    source = SCRIPT.read_text(encoding="utf-8")
    assert "compatibility-vectors-update" not in source
    assert "write_rows(args.output, rows)" in source
    print("qualification matrix: fixed gate order and validation-only vectors verified")


if __name__ == "__main__":
    main()
