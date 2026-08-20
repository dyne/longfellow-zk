#!/usr/bin/env python3
"""Emit deterministic, independent secp256k1/HASH160 BlindZap vectors."""

import hashlib
import json
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def u16(value):
    return value.to_bytes(2, "big")


def u32(value):
    return value.to_bytes(4, "big")


def u64(value):
    return value.to_bytes(8, "big")


def tagged_hash(tag, message):
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


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


def statement_vector():
    verifier = b"merchant.example"
    purpose = b"proof-of-funds"
    nonce = bytes(range(1, 33))
    message_hash = bytes(range(32, 0, -1))
    first = bytes([1]) + bytes(31) + u32(2) + u64(42) + bytes([9]) + bytes(19)
    second = bytes([2]) + bytes(31) + u32(1) + u64(99) + bytes([0, 8]) + bytes(18)
    encoded = (
        b"BZP1"
        + bytes([1, 2])  # version 1, signet
        + u16(len(verifier))
        + verifier
        + u16(len(purpose))
        + purpose
        + nonce
        + message_hash
        + u64(100)
        + u64(200)
        + bytes([0])  # no historical snapshot
        + bytes([0])  # no bridge binding
        + u16(2)
        + first
        + second
    )
    return {
        "description": "canonical two-claim signet request without snapshot or bridge binding",
        "encoded_statement": encoded.hex(),
        "statement_digest": tagged_hash("BlindZap/statement/v1", encoded).hex(),
    }


def main():
    # 1 and n-1 cover the two generator parity branches.  2 and 3 provide
    # distinct arithmetic traces.  153 and 382 are the first positive scalars
    # whose X coordinate and SHA-256 digest respectively have a leading zero.
    values = [1, 2, 3, 153, 382, N - 1]
    corpus = {
        "format": "blindzap-v1-independent-vectors",
        "generator": {
            "version": 1,
            "path": "scripts/generate_blindzap_vectors.py",
            "method": "straightforward integer secp256k1 double-and-add; hashlib SHA-256 and RIPEMD-160",
        },
        "secp256k1": {"p": f"{P:064x}", "n": f"{N:064x}"},
        "statement_v1": statement_vector(),
        "vectors": [vector(value) for value in values],
    }
    json.dump(corpus, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
