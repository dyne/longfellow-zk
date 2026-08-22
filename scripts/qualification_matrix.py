#!/usr/bin/env python3
"""Run the portable release-qualification gates and publish their raw CSV."""
from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("gate", "command", "result", "elapsed_ms")
GATES = (
    ("cpp20-contract", ("make", "cpp20-contract-test")),
    ("compatibility-lfc1", ("make", "compatibility-vectors-test")),
    ("lfc2-cross-language", ("make", "lfc2-cross-language-test")),
    ("parser-transcript-fuzz", ("make", "fuzz-smoke")),
    ("ecdsa-dense-boundaries", ("make", "ecdsa-module-test",
                                "ecdsa-proof-artifact-test", "dense-test")),
    ("ownership-boundaries", ("make", "assertion-symbols-test", "compiler-ownership-test")),
    ("metric-schema", ("make", "baseline-metrics", "baseline-metrics-test")),
)


def write_rows(output: Path, rows: list[dict[str, str | int]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", newline="", dir=output.parent,
                                     delete=False) as temporary:
        writer = csv.DictWriter(temporary, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", action="store_true",
                        help="print the fixed gate names without executing them")
    args = parser.parse_args()
    if args.plan:
        print("\n".join(name for name, _ in GATES))
        return
    if args.output is None:
        parser.error("--output is required unless --plan is used")

    rows: list[dict[str, str | int]] = []
    for name, command in GATES:
        started = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, check=False)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        rows.append({"gate": name, "command": " ".join(command),
                     "result": "pass" if result.returncode == 0 else "fail",
                     "elapsed_ms": elapsed_ms})
        write_rows(args.output, rows)
        if result.returncode:
            print(f"qualification gate failed: {name}", file=sys.stderr)
            sys.exit(result.returncode)
    print(f"wrote {len(rows)} qualification rows to {args.output}")


if __name__ == "__main__":
    main()
