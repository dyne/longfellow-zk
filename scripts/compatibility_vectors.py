#!/usr/bin/env python3
"""Create and validate reviewed C++/Rust byte-compatibility baselines.

Normal operation is validation only.  Regeneration is deliberately opt-in: it
requires both --update and --allow-reviewed-overwrite, and writes through a
temporary directory before replacing the reviewed files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "test" / "compatibility"
CPP_REPORTER = ROOT / "test" / "compatibility" / "cpp_artifact_report.cc"
RUST_REPORTER = ROOT / "test" / "compatibility" / "rust_artifact_report.rs"
RUSTC = os.environ.get("RUSTC", str(Path.home() / ".cargo" / "bin" / "rustc"))
ARTIFACTS = (
    ("transcript", "transcript", "vendor/longfellow-zk/rust/runtime/random/tests/transcript_test_vector.bin"),
    ("commitment", "commitment", "test/blindzap/testdata/blindzap_vectors.json"),
    ("proof", "proof", "test/bip340/testdata/bip340_golden.inc"),
    ("lfc1", "LFC1", "src/proto/circuit_reader.h"),
    ("verification", "verification", "vendor/longfellow-zk/rust/runtime/ligero/tests/ligero.rs"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report_lines(binary: Path, artifacts: list[str]) -> str:
    return subprocess.run([str(binary), *artifacts], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout


def cross_check(rust_report: Path | None = None, write_rust_report: Path | None = None) -> None:
    """Compare independently compiled C++ and Rust reports over each input."""
    artifacts = [relative for _, _, relative in ARTIFACTS]
    with tempfile.TemporaryDirectory(prefix="compatibility-cross-check-") as temporary:
        directory = Path(temporary)
        cpp = directory / "cpp-report"
        rust = directory / "rust-report"
        subprocess.run(["g++", "-std=c++17", str(CPP_REPORTER), "-o", str(cpp)], check=True)
        subprocess.run([RUSTC, "--edition=2021", str(RUST_REPORTER), "-o", str(rust)], check=True)
        cpp_lines = report_lines(cpp, artifacts)
        rust_lines = rust_report.read_text() if rust_report else report_lines(rust, artifacts)
        if write_rust_report:
            write_rust_report.write_text(rust_lines)
    cpp_rows = dict(line.split("\t", 1) for line in cpp_lines.splitlines())
    rust_rows = dict(line.split("\t", 1) for line in rust_lines.splitlines())
    if cpp_rows.keys() != rust_rows.keys():
        raise RuntimeError("cpp↔rust: artifact report set mismatch")
    for artifact in artifacts:
        if cpp_rows[artifact] != rust_rows[artifact]:
            raise RuntimeError(f"cpp↔rust: {artifact} byte report mismatch")


def corpus() -> dict:
    artifacts = []
    for name, kind, relative in ARTIFACTS:
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"missing provenance input: {relative}")
        artifacts.append({"name": name, "kind": kind, "path": relative,
                          "bytes": path.stat().st_size, "sha256": digest(path)})
    return {
        "format": "longfellow-zk-compatibility-v1",
        "generator": "scripts/compatibility_vectors.py",
        "provenance": {
            "cpp": "ac5d87071e0f9d1f1ef7aed855f7b6633d3f43ff",
            "rust": "vendor/longfellow-zk (git submodule)",
            "rule": "each artifact is a byte-level SHA-256 baseline",
        },
        "artifacts": artifacts,
    }


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_reviewed(directory: Path) -> None:
    value = corpus()
    payload = encoded(value)
    manifest = {
        "format": "longfellow-zk-compatibility-manifest-v1",
        "vectors": "vectors.json",
        "vectors_sha256": hashlib.sha256(payload).hexdigest(),
    }
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compatibility-vectors-", dir=directory.parent) as temporary:
        staging = Path(temporary)
        (staging / "vectors.json").write_bytes(payload)
        (staging / "manifest.json").write_bytes(encoded(manifest))
        os.replace(staging / "vectors.json", directory / "vectors.json")
        os.replace(staging / "manifest.json", directory / "manifest.json")


def check(directory: Path, implementation: str) -> None:
    vectors_path = directory / "vectors.json"
    manifest_path = directory / "manifest.json"
    if not vectors_path.is_file() or not manifest_path.is_file():
        raise RuntimeError("reviewed vectors or manifest is missing")
    reviewed = json.loads(vectors_path.read_text())
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("vectors_sha256") != hashlib.sha256(vectors_path.read_bytes()).hexdigest():
        raise RuntimeError("manifest hash mismatch")
    expected = {item[0]: item for item in ARTIFACTS}
    actual = {item.get("name"): item for item in reviewed.get("artifacts", [])}
    if set(actual) != set(expected):
        raise RuntimeError("artifact set mismatch")
    for name, (_, _, relative) in expected.items():
        item = actual[name]
        path = ROOT / relative
        if item.get("path") != relative or item.get("sha256") != digest(path):
            raise RuntimeError(f"{implementation}: {name} hash mismatch")
        if item.get("bytes") != path.stat().st_size:
            raise RuntimeError(f"{implementation}: {name} size mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--allow-reviewed-overwrite", action="store_true")
    parser.add_argument("--implementation", choices=("cpp", "rust"), default="cpp")
    parser.add_argument("--rust-report", type=Path)
    parser.add_argument("--write-rust-report", type=Path)
    args = parser.parse_args()
    if args.update:
        if not args.allow_reviewed_overwrite:
            parser.error("--update requires --allow-reviewed-overwrite")
        write_reviewed(args.directory)
        print(f"updated reviewed compatibility vectors: {args.directory}")
    cross_check(args.rust_report, args.write_rust_report)
    check(args.directory, args.implementation)
    print(f"{args.implementation}: compatibility vectors verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"compatibility-vector failure: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
