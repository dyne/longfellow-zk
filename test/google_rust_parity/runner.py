#!/usr/bin/env python3
"""Deterministic, locale-independent version-1 parity record driver."""
from __future__ import annotations
import argparse, hashlib, os, struct, subprocess, sys, tempfile

MAGIC = b"LFP1"; VERSION = 1; TYPE_OUTCOME = 1
HEADER = struct.Struct("<4sBBI")

class RecordError(ValueError): pass

def encode(key: int, outcome: int, digest: bytes) -> bytes:
    if not (0 <= key <= 0xffffffff and outcome in (0, 1) and len(digest) == 32): raise RecordError("invalid canonical field")
    body = struct.pack("<IB", key, outcome) + digest
    return HEADER.pack(MAGIC, VERSION, TYPE_OUTCOME, len(body)) + body

def decode(blob: bytes) -> dict[int, tuple[int, bytes]]:
    offset = 0; records = {}
    while offset < len(blob):
        if len(blob) - offset < HEADER.size: raise RecordError("truncated header")
        magic, version, kind, length = HEADER.unpack_from(blob, offset); offset += HEADER.size
        if magic != MAGIC: raise RecordError("unknown magic")
        if version != VERSION: raise RecordError("unknown version")
        if kind != TYPE_OUTCOME: raise RecordError("unknown record type")
        if length != 37 or len(blob) - offset < length: raise RecordError("truncated record")
        key, outcome = struct.unpack_from("<IB", blob, offset)
        digest = blob[offset + 5:offset + length]; offset += length
        if outcome not in (0, 1): raise RecordError("invalid normalized outcome")
        if key in records: raise RecordError("duplicate record key")
        records[key] = (outcome, digest)
    if not records: raise RecordError("missing record keys")
    return records

def invoke(exe: str, corpus: str, output: str) -> dict[int, tuple[int, bytes]]:
    result = subprocess.run([exe, corpus, output], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode: raise RecordError("oracle failure")
    return decode(open(output, "rb").read())

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--cpp", required=True); parser.add_argument("--rust", required=True); parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    # This deliberately contains no proofs/witnesses: only public deterministic digests.
    corpus = b"".join(encode(key, 1, hashlib.sha256(struct.pack("<I", key)).digest()) for key in (1, 2, 3))
    try:
        with tempfile.TemporaryDirectory(prefix="google-rust-parity-") as temp:
            source = os.path.join(temp, "corpus.bin"); open(source, "wb").write(corpus)
            left = invoke(args.cpp, source, os.path.join(temp, "cpp.bin")); right = invoke(args.rust, source, os.path.join(temp, "rust.bin"))
    except (OSError, RecordError) as error:
        print(f"google-rust-parity: {error}", file=sys.stderr); return 1
    if left.keys() != right.keys(): print("google-rust-parity: missing record key", file=sys.stderr); return 1
    for key in sorted(left):
        if left[key] != right[key]:
            print(f"google-rust-parity: mismatch primitive=placeholder case={key} commit={args.commit} outcomes={left[key][0]}/{right[key][0]}", file=sys.stderr); return 1
    print(f"google-rust-parity: commit={args.commit} records={len(left)} equal")
    return 0

if __name__ == "__main__": raise SystemExit(main())
