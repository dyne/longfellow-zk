#!/usr/bin/env sage
"""Independent executable specification for the BlindZap v1 relation.

Sage supplies finite-field and elliptic-curve arithmetic.  SHA-256 and
RIPEMD-160 are implemented directly below instead of delegated to OpenSSL or
Python's hashlib, so this model can catch padding and byte-order disagreements
with the production implementation and the existing Python vector generator.
"""

import argparse
import json
import sys

from sage.all import EllipticCurve, GF, Integer, is_prime


P = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
N = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
GX = Integer(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
GY = Integer(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
MASK32 = (1 << 32) - 1

SHA256_INITIAL = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

RIPEMD_R_LEFT = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
RIPEMD_R_RIGHT = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
RIPEMD_S_LEFT = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
RIPEMD_S_RIGHT = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
RIPEMD_K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
RIPEMD_K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def u16(value):
    return int(value).to_bytes(2, "big")


def u32(value):
    return int(value).to_bytes(4, "big")


def u64(value):
    return int(value).to_bytes(8, "big")


def rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK32


def rotate_left(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def sha256(message):
    padded = bytearray(message)
    bit_length = len(padded) * 8
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(bit_length.to_bytes(8, "big"))
    state = list(SHA256_INITIAL)
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        words = [int.from_bytes(block[index:index + 4], "big")
                 for index in range(0, 64, 4)]
        for index in range(16, 64):
            x = words[index - 15]
            y = words[index - 2]
            sigma0 = rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)
            sigma1 = rotate_right(y, 17) ^ rotate_right(y, 19) ^ (y >> 10)
            words.append((words[index - 16] + sigma0 + words[index - 7] + sigma1) & MASK32)
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            upper_e = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
            choose = (e & f) ^ ((~e) & g)
            temporary1 = (h + upper_e + choose + SHA256_K[index] + words[index]) & MASK32
            upper_a = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (upper_a + majority) & MASK32
            h, g, f, e, d, c, b, a = g, f, e, (d + temporary1) & MASK32, c, b, a, (temporary1 + temporary2) & MASK32
        state = [(old + new) & MASK32 for old, new in zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(word.to_bytes(4, "big") for word in state)


def ripemd_function(round_index, x, y, z):
    if round_index < 16:
        return x ^ y ^ z
    if round_index < 32:
        return (x & y) | ((~x) & z)
    if round_index < 48:
        return (x | (~y)) ^ z
    if round_index < 64:
        return (x & z) | (y & (~z))
    return x ^ (y | (~z))


def ripemd160(message):
    padded = bytearray(message)
    bit_length = len(padded) * 8
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(bit_length.to_bytes(8, "little"))
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        words = [int.from_bytes(block[index:index + 4], "little")
                 for index in range(0, 64, 4)]
        al, bl, cl, dl, el = state
        ar, br, cr, dr, er = state
        for index in range(80):
            left = rotate_left((al + ripemd_function(index, bl, cl, dl) +
                                words[RIPEMD_R_LEFT[index]] +
                                RIPEMD_K_LEFT[index // 16]) & MASK32,
                               RIPEMD_S_LEFT[index])
            left = (left + el) & MASK32
            al, el, dl, cl, bl = el, dl, rotate_left(cl, 10), bl, left
            right = rotate_left((ar + ripemd_function(79 - index, br, cr, dr) +
                                 words[RIPEMD_R_RIGHT[index]] +
                                 RIPEMD_K_RIGHT[index // 16]) & MASK32,
                                RIPEMD_S_RIGHT[index])
            right = (right + er) & MASK32
            ar, er, dr, cr, br = er, dr, rotate_left(cr, 10), br, right
        temporary = (state[1] + cl + dr) & MASK32
        state[1] = (state[2] + dl + er) & MASK32
        state[2] = (state[3] + el + ar) & MASK32
        state[3] = (state[4] + al + br) & MASK32
        state[4] = (state[0] + bl + cr) & MASK32
        state[0] = temporary
    return b"".join(word.to_bytes(4, "little") for word in state)


def tagged_hash(tag, message):
    tag_digest = sha256(tag.encode("ascii"))
    return sha256(tag_digest + tag_digest + message)


FIELD = GF(P)
CURVE = EllipticCurve(FIELD, [0, 7])
GENERATOR = CURVE(FIELD(GX), FIELD(GY))
INFINITY = CURVE(0)


def valid_scalar(value):
    scalar = Integer(value)
    if scalar <= 0 or scalar >= N:
        raise ValueError("secret scalar must satisfy 1 <= x < n")
    return scalar


def compressed_sec(point):
    if point == INFINITY:
        raise ValueError("point at infinity has no compressed SEC encoding")
    x = Integer(point[0])
    y = Integer(point[1])
    return bytes([2 + int(y & 1)]) + int(x).to_bytes(32, "big")


def decompress_sec(sec):
    if len(sec) != 33 or sec[0] not in (2, 3):
        raise ValueError("compressed SEC must be 33 bytes with prefix 02 or 03")
    x_integer = Integer(int.from_bytes(sec[1:], "big"))
    if x_integer >= P:
        raise ValueError("compressed SEC x coordinate is not canonical")
    x = FIELD(x_integer)
    square = x**3 + 7
    if not square.is_square():
        raise ValueError("compressed SEC does not encode a curve point")
    y = square.sqrt()
    if int(Integer(y)) & 1 != sec[0] - 2:
        y = -y
    point = CURVE(x, y)
    if compressed_sec(point) != sec:
        raise AssertionError("compressed SEC round trip failed")
    return point


def relation_vector(scalar):
    scalar = valid_scalar(scalar)
    point = scalar * GENERATOR
    sec = compressed_sec(point)
    sha_digest = sha256(sec)
    program = ripemd160(sha_digest)
    if decompress_sec(sec) != point:
        raise AssertionError("SEC decompression disagrees with scalar multiplication")
    return {
        "secret_scalar": str(scalar),
        "x_coordinate": f"{int(Integer(point[0])):064x}",
        "y_coordinate": f"{int(Integer(point[1])):064x}",
        "y_parity": int(Integer(point[1])) & 1,
        "compressed_sec": sec.hex(),
        "sha256": sha_digest.hex(),
        "hash160": program.hex(),
        "p2wpkh_script_pubkey": (b"\x00\x14" + program).hex(),
    }


def statement_vector():
    verifier = b"merchant.example"
    purpose = b"proof-of-funds"
    nonce = bytes(range(1, 33))
    message_hash = bytes(range(32, 0, -1))
    first = bytes([1]) + bytes(31) + u32(2) + u64(42) + bytes([9]) + bytes(19)
    second = bytes([2]) + bytes(31) + u32(1) + u64(99) + bytes([0, 8]) + bytes(18)
    encoded = (b"BZP1" + bytes([1, 2]) + u16(len(verifier)) + verifier +
               u16(len(purpose)) + purpose + nonce + message_hash + u64(100) +
               u64(200) + bytes([0, 0]) + u16(2) + first + second)
    digest = tagged_hash("BlindZap/statement/v1", encoded)
    circuit_digest = bytes(range(1, 33))
    transcript_binding = digest + circuit_digest + u32(1) + u32(4) + u32(128)
    return {
        "description": "canonical two-claim signet request without snapshot or bridge binding",
        "encoded_statement": encoded.hex(),
        "statement_digest": digest.hex(),
        "transcript_example": {
            "circuit_digest": circuit_digest.hex(),
            "circuit_version": 1,
            "rate": 4,
            "queries": 128,
            "seed": tagged_hash("BlindZap/transcript/v1", transcript_binding).hex(),
        },
    }


def first_non_residue_x():
    candidate = Integer(0)
    while (FIELD(candidate)**3 + 7).is_square():
        candidate += 1
    return candidate


def build_corpus():
    if not is_prime(P) or not is_prime(N):
        raise AssertionError("secp256k1 field modulus and subgroup order must be prime")
    if GENERATOR == INFINITY or N * GENERATOR != INFINITY:
        raise AssertionError("generator does not have the specified subgroup order")
    if (N - 1) * GENERATOR != -GENERATOR:
        raise AssertionError("scalar negation identity failed")
    if sha256(b"").hex() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise AssertionError("SHA-256 empty-message self-test failed")
    if sha256(b"abc").hex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        raise AssertionError("SHA-256 abc self-test failed")
    if ripemd160(b"").hex() != "9c1185a5c5e9fc54612808977ee8f548b2258d31":
        raise AssertionError("RIPEMD-160 empty-message self-test failed")
    if ripemd160(b"abc").hex() != "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc":
        raise AssertionError("RIPEMD-160 abc self-test failed")
    padding_55 = bytes(range(55))
    padding_56 = bytes(range(56))
    if sha256(padding_55).hex() != "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59":
        raise AssertionError("SHA-256 55-byte padding-boundary self-test failed")
    if sha256(padding_56).hex() != "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562":
        raise AssertionError("SHA-256 56-byte padding-boundary self-test failed")
    if ripemd160(padding_55).hex() != "3c86963b3ff646a65ae42996e9664c747cc7e5e6":
        raise AssertionError("RIPEMD-160 55-byte padding-boundary self-test failed")
    if ripemd160(padding_56).hex() != "ebdd79cfd4fd9949ef8089673d2620427f487cfb":
        raise AssertionError("RIPEMD-160 56-byte padding-boundary self-test failed")

    scalar_values = [1, 2, 3, 153, 382, N - 1]
    invalid_scalars = (-1, 0, N, N + 1)
    for scalar in invalid_scalars:
        try:
            valid_scalar(scalar)
        except ValueError:
            continue
        raise AssertionError(f"invalid scalar accepted: {scalar}")

    non_residue = first_non_residue_x()
    invalid_sec = (
        bytes([4]) + bytes(32),
        bytes([2]) + int(P).to_bytes(32, "big"),
        bytes([2]) + int(non_residue).to_bytes(32, "big"),
    )
    for sec in invalid_sec:
        try:
            decompress_sec(sec)
        except ValueError:
            continue
        raise AssertionError(f"invalid compressed SEC accepted: {sec.hex()}")

    return {
        "format": "blindzap-v1-sage-reference-vectors",
        "generator": {
            "version": 1,
            "path": "spec/blindzap/blindzap_reference.sage",
            "method": "Sage GF(p) elliptic curve; independent SHA-256 and RIPEMD-160 compression functions",
        },
        "secp256k1": {
            "p": f"{int(P):064x}",
            "n": f"{int(N):064x}",
            "generator_x": f"{int(GX):064x}",
            "generator_y": f"{int(GY):064x}",
            "p_is_prime": True,
            "n_is_prime": True,
            "n_times_generator_is_infinity": True,
            "n_minus_one_times_generator_is_negative_generator": True,
        },
        "hash_self_tests": {
            "sha256_empty": sha256(b"").hex(),
            "sha256_abc": sha256(b"abc").hex(),
            "sha256_55_bytes": sha256(padding_55).hex(),
            "sha256_56_bytes": sha256(padding_56).hex(),
            "ripemd160_empty": ripemd160(b"").hex(),
            "ripemd160_abc": ripemd160(b"abc").hex(),
            "ripemd160_55_bytes": ripemd160(padding_55).hex(),
            "ripemd160_56_bytes": ripemd160(padding_56).hex(),
        },
        "statement_v1": statement_vector(),
        "invalid_scalars": [
            {"secret_scalar": str(value), "reason": "outside canonical interval 1 <= x < n"}
            for value in invalid_scalars
        ],
        "invalid_compressed_sec": [
            {"compressed_sec": invalid_sec[0].hex(), "reason": "unsupported prefix"},
            {"compressed_sec": invalid_sec[1].hex(), "reason": "x coordinate is p, not canonical"},
            {"compressed_sec": invalid_sec[2].hex(), "reason": "x^3 + 7 is a quadratic non-residue"},
        ],
        "vectors": [relation_vector(value) for value in scalar_values],
    }


def common_projection(corpus):
    statement = dict(corpus["statement_v1"])
    statement.pop("transcript_example", None)
    return {
        "secp256k1": {"p": corpus["secp256k1"]["p"], "n": corpus["secp256k1"]["n"]},
        "statement_v1": statement,
        "vectors": corpus["vectors"],
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", metavar="PATH", help="require exact equality with a checked-in Sage fixture")
    parser.add_argument("--cross-check", metavar="PATH", help="compare shared fields with the independent Python fixture")
    parser.add_argument("--emit", action="store_true", help="emit the canonical Sage corpus to stdout")
    arguments = parser.parse_args()
    corpus = build_corpus()
    failed = False
    if arguments.check and corpus != load_json(arguments.check):
        print(f"Sage corpus differs from {arguments.check}", file=sys.stderr)
        failed = True
    if arguments.cross_check:
        python_corpus = load_json(arguments.cross_check)
        if common_projection(corpus) != common_projection(python_corpus):
            print(f"Sage/Python shared vectors differ: {arguments.cross_check}", file=sys.stderr)
            failed = True
    if arguments.emit or (not arguments.check and not arguments.cross_check):
        json.dump(corpus, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    if failed:
        return 1
    if arguments.check or arguments.cross_check:
        print("BlindZap Sage reference checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
