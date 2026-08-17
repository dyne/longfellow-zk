#!/usr/bin/env python3
"""Keep required normative specification anchors from silently disappearing."""

from pathlib import Path
import sys

text = Path("docs/blindzap-v1.md").read_text(encoding="utf-8")
required = [
    "## 1. Conventions and constants",
    "## 2. Circuit input layout",
    "## 3. Protocol statement",
    "## 4. Verification and result selection",
    "HASH160(SEC_compressed(xG)) = program",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    "invalid_proof",
    "valid_current",
]
missing = [anchor for anchor in required if anchor not in text]
if missing:
    print("missing specification anchors: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)

order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
prime = "fffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
source_text = "\n".join(
    Path(path).read_text(encoding="utf-8").lower()
    for path in ("src/ec/p256k1.cc", "src/ec/p256k1.h", "src/circuits/bip340/bip340_witness.h")
)
if order not in source_text or prime not in source_text:
    print("repository secp256k1 constants no longer match the normative specification", file=sys.stderr)
    sys.exit(1)
