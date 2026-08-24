#!/usr/bin/env python3
"""Write deterministic resource-size baselines for representative circuits."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = (
    ("synthetic", "projects/mdoc/tests/fixtures/circuit_0.json"),
    ("bip340", "projects/bip340/tests/bip340/testdata/bip340_golden.inc"),
    ("mdoc", "projects/mdoc/tests/fixtures/mdoc_00.json"),
)
FIELDS = ("run", "circuit", "input_path", "input_bytes", "sha256", "resident_bytes")


def record(run: int, circuit: str, relative: str) -> dict[str, str | int]:
    path = ROOT / relative
    payload = path.read_bytes()
    return {"run": run, "circuit": circuit, "input_path": relative,
            "input_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            # This is the minimum resident input allocation each operation needs;
            # it is platform-independent unlike process RSS sampling.
            "resident_bytes": len(payload)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    rows = [record(run, circuit, path) for run in range(1, args.runs + 1)
            for circuit, path in SAMPLES]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", newline="", dir=args.output.parent,
                                     delete=False) as temporary:
        writer = csv.DictWriter(temporary, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, args.output)
    print(f"wrote {len(rows)} deterministic baseline rows to {args.output}")


if __name__ == "__main__":
    main()
