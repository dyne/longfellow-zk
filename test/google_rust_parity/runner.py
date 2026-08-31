#!/usr/bin/env python3
"""Deterministic, locale-independent version-1 parity record driver."""
from __future__ import annotations
import argparse, os, struct, subprocess, sys, tempfile, time

MAGIC = b"LFP2"; VERSION = 1; TYPE_OUTCOME = 1
HEADER = struct.Struct("<4sBBI")

CASE_NAMES = {
    1: "transcript.empty-draw-31", 2: "transcript.length-boundaries",
    3: "transcript.typed-writes", 4: "transcript.clone-after-draw",
    5: "transcript.clone-prf-boundary", 6: "transcript.large-draw",
    10: "field.gf2-128-arithmetic", 11: "field.p256-base-arithmetic",
    12: "field.p256-scalar-arithmetic", 13: "field.p256-noncanonical-decode",
    14: "field.boundary-encodings", 15: "field.extended-operations",
    20: "coding.lch14-fft-offset", 21: "coding.reed-solomon-5-to-13",
    22: "coding.gf2-basis", 23: "coding.lch14-sparse-fft",
    24: "coding.reed-solomon-8-to-8", 25: "coding.reed-solomon-3-to-8",
    30: "curve.generator-double-scalar", 31: "curve.negation",
    32: "curve.order-boundaries", 33: "curve.seeded-scalar",
    34: "curve.identity", 35: "curve.addition",
    40: "merkle.power-of-two-proof", 41: "merkle.non-power-of-two-proof",
    42: "merkle.commitment-proof", 50: "circuit.lfc-codecs",
    60: "ligero.geometry", 61: "ligero.commitment", 62: "ligero.proof-shape",
    63: "ligero.valid-and-tampered", 70: "zk.rfc-commitment-and-verification",
}

class RecordError(ValueError): pass

def encode(key: int, outcome: int, value: bytes) -> bytes:
    if not (0 <= key <= 0xffffffff and outcome in (0, 1)): raise RecordError("invalid canonical field")
    body = struct.pack("<IB", key, outcome) + value
    return HEADER.pack(MAGIC, VERSION, TYPE_OUTCOME, len(body)) + body

def decode(blob: bytes) -> dict[int, tuple[int, bytes]]:
    offset = 0; records = {}
    while offset < len(blob):
        if len(blob) - offset < HEADER.size: raise RecordError("truncated header")
        magic, version, kind, length = HEADER.unpack_from(blob, offset); offset += HEADER.size
        if magic != MAGIC: raise RecordError("unknown magic")
        if version != VERSION: raise RecordError("unknown version")
        if kind != TYPE_OUTCOME: raise RecordError("unknown record type")
        if length < 5 or len(blob) - offset < length: raise RecordError("truncated record")
        key, outcome = struct.unpack_from("<IB", blob, offset)
        value = blob[offset + 5:offset + length]; offset += length
        if outcome not in (0, 1): raise RecordError("invalid normalized outcome")
        if key in records: raise RecordError("duplicate record key")
        records[key] = (outcome, value)
    if not records: raise RecordError("missing record keys")
    return records

def invoke(exe: str, corpus: str, output: str) -> tuple[dict[int, tuple[int, bytes]], float]:
    started = time.perf_counter()
    result = subprocess.run([exe, corpus, output], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode: raise RecordError("oracle failure")
    return decode(open(output, "rb").read()), time.perf_counter() - started

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--cpp", required=True); parser.add_argument("--rust", required=True); parser.add_argument("--commit", required=True); parser.add_argument("--subset", choices=("all", "transcript", "field", "coding", "curve", "merkle", "circuit", "ligero", "zk"), default="all"); parser.add_argument("--timings", action="store_true", help="report non-normative oracle elapsed times")
    args = parser.parse_args()
    # The corpus is a versioned selector, not a duplicated primitive implementation.
    corpus = b"".join(encode(key, 1, b"") for key in (1, 2, 3, 4, 5))
    try:
        with tempfile.TemporaryDirectory(prefix="google-rust-parity-") as temp:
            source = os.path.join(temp, "corpus.bin"); open(source, "wb").write(corpus)
            left, cpp_seconds = invoke(args.cpp, source, os.path.join(temp, "cpp.bin")); right, rust_seconds = invoke(args.rust, source, os.path.join(temp, "rust.bin"))
    except (OSError, RecordError) as error:
        print(f"google-rust-parity: {error}", file=sys.stderr); return 1
    keys = set(range(1, 7)) if args.subset == "transcript" else set(range(10, 16)) if args.subset == "field" else set(range(20, 26)) if args.subset == "coding" else set(range(30, 36)) if args.subset == "curve" else set(range(40, 43)) if args.subset == "merkle" else {50} if args.subset == "circuit" else {60, 61, 62, 63} if args.subset == "ligero" else {70} if args.subset == "zk" else set(left)
    if left.keys() != right.keys() or not keys <= left.keys(): print("google-rust-parity: missing record key", file=sys.stderr); return 1
    for key in sorted(keys):
        if left[key] != right[key]:
            print(f"google-rust-parity: mismatch primitive={args.subset} case={key} commit={args.commit} outcomes={left[key][0]}/{right[key][0]}", file=sys.stderr); return 1
        print(f"google-rust-parity: record={key} name={CASE_NAMES.get(key, 'unknown')} bytes={len(left[key][1])} outcome={left[key][0]} equal")
    print(f"google-rust-parity: subset={args.subset} commit={args.commit} records={len(keys)} equal")
    if args.timings:
        print(f"google-rust-parity: timings cpp_ms={cpp_seconds * 1000:.1f} rust_ms={rust_seconds * 1000:.1f} (non-normative)")
    return 0

if __name__ == "__main__": raise SystemExit(main())
