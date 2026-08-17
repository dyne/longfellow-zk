#!/bin/bash

set -Eeuo pipefail

readarray -t sources <<EOF

ec/p256.cc algebra/nat.cc circuits/sha/flatsha256_witness.cc
circuits/sha/sha256_constants.cc circuits/tests/base64/decode_util.cc
circuits/mdoc/mdoc_zk.cc circuits/mdoc/zk_spec.cc
circuits/mdoc/mdoc_decompress.cc circuits/mdoc/mdoc_generate_circuit.cc
EOF

readarray -t optional_sources <<EOF
ec/p256k1.cc algebra/crt.cc
EOF

readarray -t headers <<EOF

algebra/fp.h algebra/fp_generic.h util/serialization.h
util/readbuffer.h algebra/static_string.h algebra/sysdep.h
algebra/fp_p256.h ec/elliptic_curve.h util/ceildiv.h
algebra/convolution.h algebra/blas.h algebra/fft.h
algebra/permutations.h algebra/twiddle.h algebra/rfft.h algebra/fp2.h
algebra/reed_solomon.h algebra/utility.h arrays/dense.h algebra/poly.h
arrays/affine.h circuits/compiler/circuit_dump.h
circuits/compiler/compiler.h algebra/hash.h util/crc64.h
sumcheck/circuit_id.h sumcheck/circuit.h sumcheck/quad.h
algebra/compare.h arrays/eqs.h circuits/compiler/node.h
circuits/compiler/pdqhash.h circuits/compiler/schedule.h
circuits/mdoc/mdoc_decompress.h circuits/mdoc/mdoc_attribute_ids.h
circuits/logic/bit_plucker.h algebra/interpolation.h
circuits/logic/bit_plucker_constants.h circuits/logic/polynomial.h
circuits/logic/compiler_backend.h circuits/logic/logic.h
gf2k/gf2_128.h gf2k/gf2poly.h circuits/mac/mac_circuit.h
circuits/mac/mac_reference.h random/random.h
circuits/mac/mac_witness.h circuits/logic/bit_plucker_encoder.h
circuits/mdoc/mdoc_hash.h
circuits/logic/memcmp.h circuits/logic/routing.h
circuits/mdoc/mdoc_constants.h circuits/sha/flatsha256_circuit.h
circuits/logic/bit_adder.h circuits/mdoc/mdoc_signature.h
circuits/ecdsa/verify_circuit.h circuits/mdoc/mdoc_witness.h
cbor/host_decoder.h circuits/ecdsa/verify_witness.h
gf2k/lch14_reed_solomon.h gf2k/lch14.h sumcheck/circuit.h
random/secure_random_engine.h random/transcript.h zk/zk_proof.h
ligero/ligero_param.h merkle/merkle_commitment.h merkle/merkle_tree.h
zk/zk_common.h arrays/eq.h sumcheck/transcript_sumcheck.h
zk/zk_prover.h ligero/ligero_prover.h ligero/ligero_transcript.h
sumcheck/prover_layers.h zk/zk_verifier.h ligero/ligero_verifier.h
circuits/cbor_parser/cbor_byte_decoder.h circuits/logic/counter.h
proto/circuit_io.h proto/circuit_reader.h proto/circuit_writer.h
sumcheck/equad.h sumcheck/hquad.h sumcheck/quad_builder.h

EOF

readarray -t optional_headers <<EOF
algebra/fp_p256k1.h algebra/crt.h algebra/crt_convolution.h
ec/p256k1.h circuits/logic/evaluation_backend.h

EOF

readarray -t bip340_headers <<EOF
bip340_verify.h
bip340_witness.h
bip340_guard.h

EOF

readarray -t bip340_testdata <<EOF
bip340_vectors.inc
bip340_golden.inc
bip340_test_vectors.csv

EOF

[[ "${1:-}" == "clean" ]] && {
  for i in ${sources[@]}; do
    rm -f src/$i
  done
  for i in ${optional_sources[@]}; do
    rm -f src/$i
  done
  for i in ${headers[@]}; do
    rm -f src/$i
  done
  for i in ${optional_headers[@]}; do
    rm -f src/$i
  done
  for i in "${bip340_headers[@]}"; do
    [[ -z "$i" ]] || rm -f "src/circuits/bip340/$i"
  done
  for i in "${bip340_testdata[@]}"; do
    [[ -z "$i" ]] || rm -f "test/bip340/testdata/$i"
  done
  exit 0
}

[[ -z "${1:-}" ]] && {
	>&2 echo "usage: $0 [bip340] path/to/longfellow-zk"
	exit 1
}

bip340_only=false
if [[ "$1" == "bip340" ]]; then
	bip340_only=true
	shift
fi

[[ -z "${1:-}" ]] && {
	>&2 echo "usage: $0 [bip340] path/to/longfellow-zk"
	exit 1
}

[[ -d "$1/lib/ligero" ]] || {
	>&2 echo "not found: $1"
	exit 1
}

copy_optional() {
	local from="$1"
	local to="$2"
	if [[ -r "$from" ]]; then
		cp "$from" "$to"
	elif [[ -r "$to" ]]; then
		>&2 echo "keeping checked-in optional import: $to"
	else
		>&2 echo "optional upstream file missing and no checked-in copy: $from"
		exit 1
	fi
}

if [[ -d "$1/lib/circuits/tests/contrib/bip340" ]]; then
	bip340_upstream="$1/lib/circuits/tests/contrib/bip340"
elif [[ -d "$1/lib/circuits/bip340" ]]; then
	# Compatibility with the circuit's pre-contribution layout.
	bip340_upstream="$1/lib/circuits/bip340"
else
	bip340_upstream=""
	if $bip340_only; then
		>&2 echo "BIP-340 upstream source not found below $1/lib/circuits"
		exit 1
	fi
fi

import_bip340() {
	if [[ -z "$bip340_upstream" ]]; then
		>&2 echo "keeping checked-in BIP-340 import (not present upstream)"
		return
	fi
	for i in "${bip340_headers[@]}"; do
		[[ -z "$i" ]] && continue
		mkdir -p src/circuits/bip340
		copy_optional "$bip340_upstream/$i" "src/circuits/bip340/$i"
		perl -pi -e 's/CIRCUITS_TESTS_CONTRIB_BIP340/CIRCUITS_BIP340/g' \
			"src/circuits/bip340/$i"
	done

	for i in "${bip340_testdata[@]}"; do
		[[ -z "$i" ]] && continue
		mkdir -p test/bip340/testdata
		copy_optional "$bip340_upstream/testdata/$i" "test/bip340/testdata/$i"
	done

	# This distribution supplies its portable SHA-256 adapter instead of
	# linking the contributed circuit directly to OpenSSL.
	perl -0pi -e 's|// OpenSSL for SHA-256 \(already a project dependency\)\.\n#include <openssl/sha\.h>|#include "util/crypto.h"|' src/circuits/bip340/bip340_witness.h
	perl -0pi -e 's|uint8_t tag_hash\[32\];\n    SHA256_CTX ctx;\n    SHA256_Init\(&ctx\);\n    SHA256_Update\(&ctx, tag, tag_len\);\n    SHA256_Final\(tag_hash, &ctx\);|uint8_t tag_hash[32];\n    SHA256 tag_sha;\n    tag_sha.Update(reinterpret_cast<const uint8_t*>(tag), tag_len);\n    tag_sha.DigestData(tag_hash);|' src/circuits/bip340/bip340_witness.h
	perl -0pi -e 's|SHA256_Init\(&ctx\);\n    SHA256_Update\(&ctx, tag_hash, 32\);\n    SHA256_Update\(&ctx, tag_hash, 32\);\n    SHA256_Update\(&ctx, r_bytes, 32\);\n    SHA256_Update\(&ctx, pk_bytes, 32\);\n    SHA256_Update\(&ctx, msg, msg_len\);\n    SHA256_Final\(hash, &ctx\);|SHA256 challenge_sha;\n    challenge_sha.Update(tag_hash, 32);\n    challenge_sha.Update(tag_hash, 32);\n    challenge_sha.Update(r_bytes, 32);\n    challenge_sha.Update(pk_bytes, 32);\n    challenge_sha.Update(msg, msg_len);\n    challenge_sha.DigestData(hash);|' src/circuits/bip340/bip340_witness.h
}

if $bip340_only; then
	import_bip340
	>&2 echo "🌉 BIP-340 imported from $bip340_upstream"
	exit 0
fi

echo "SOURCES := \\" > src/sources.mk
for i in ${sources[@]}; do
	mkdir -p src/`dirname $i`
	cc="${1}/lib/${i}"
	h="${cc%.cc}.h"
	cp "$cc" src/"$i"
	[ -r "$h" ] && cp "$h" "src/${i%.cc}.h"
	echo "${i}.o \\" >> src/sources.mk
done
for i in ${optional_sources[@]}; do
	mkdir -p src/`dirname $i`
	cc="${1}/lib/${i}"
	h="${cc%.cc}.h"
	copy_optional "$cc" src/"$i"
	[ -r "$h" ] && cp "$h" "src/${i%.cc}.h"
	echo "${i}.o \\" >> src/sources.mk
done

for i in ${headers[@]}; do
	mkdir -p src/`dirname $i`
	h="${1}/lib/${i}"
	cp "$h" src/"$i"
done
for i in ${optional_headers[@]}; do
	mkdir -p src/`dirname $i`
	h="${1}/lib/${i}"
	copy_optional "$h" src/"$i"
done

import_bip340

>&2 echo "🌉 Upstream source imported from $1"
exit 0
