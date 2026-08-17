#!/usr/bin/env python3
"""Emit deterministic, independent secp256k1/HASH160 BlindZap vectors."""

import hashlib
import json
import platform
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = ((3 * x1 * x1) * pow(2 * y1, -1, P) if a == b else
             (y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(scalar):
    result = None
    point = (GX, GY)
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def vector(scalar):
    x, y = multiply(scalar)
    sec = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    sha256 = hashlib.sha256(sec).digest()
    h160 = hashlib.new("ripemd160", sha256).digest()
    return {
        "secret_scalar": str(scalar),
        "x_coordinate": x.to_bytes(32, "big").hex(),
        "y_coordinate": y.to_bytes(32, "big").hex(),
        "y_parity": y & 1,
        "compressed_sec": sec.hex(),
        "sha256": sha256.hex(),
        "hash160": h160.hex(),
        "p2wpkh_script_pubkey": (b"\x00\x14" + h160).hex(),
    }


def main():
    # 1 and n-1 cover the two generator parity branches.  2 and 3 provide
    # distinct arithmetic traces.  153 and 382 are the first positive scalars
    # whose X coordinate and SHA-256 digest respectively have a leading zero.
    values = [1, 2, 3, 153, 382, N - 1]
    corpus = {
        "format": "blindzap-v1-independent-vectors",
        "generator": {
            "path": "scripts/generate_blindzap_vectors.py",
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "hashlib_openssl": getattr(hashlib, "openssl_version", "implementation-provided"),
            "method": "straightforward integer secp256k1 double-and-add; hashlib SHA-256 and RIPEMD-160",
        },
        "secp256k1": {"p": f"{P:064x}", "n": f"{N:064x}"},
        "vectors": [vector(value) for value in values],
    }
    json.dump(corpus, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
