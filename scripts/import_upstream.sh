#!/bin/bash

set -e

readarray -t sources <<EOF

ec/p256.cc algebra/nat.cc circuits/sha/flatsha256_witness.cc
circuits/sha/sha256_constants.cc circuits/base64/decode_util.cc
circuits/mdoc/mdoc_zk.cc circuits/mdoc/zk_spec.cc
circuits/sha3/sha3_reference.cc circuits/sha3/sha3_round_constants.cc

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
circuits/compiler/circuit_id.h sumcheck/circuit.h sumcheck/quad.h
algebra/compare.h arrays/eqs.h circuits/compiler/node.h
circuits/compiler/pdqhash.h circuits/compiler/schedule.h
circuits/logic/bit_plucker.h algebra/interpolation.h
circuits/logic/bit_plucker_constants.h circuits/logic/polynomial.h
circuits/logic/compiler_backend.h circuits/logic/logic.h
gf2k/gf2_128.h gf2k/gf2poly.h gf2k/sysdep.h circuits/mac/mac_circuit.h
circuits/mac/mac_reference.h random/random.h
circuits/mac/mac_witness.h circuits/logic/bit_plucker_encoder.h
circuits/mdoc/mdoc_examples.h circuits/mdoc/mdoc_hash.h
circuits/logic/memcmp.h circuits/logic/routing.h
circuits/mdoc/mdoc_constants.h circuits/sha/flatsha256_circuit.h
circuits/logic/bit_adder.h circuits/mdoc/mdoc_signature.h
circuits/ecdsa/verify_circuit.h circuits/mdoc/mdoc_witness.h
cbor/host_decoder.h circuits/ecdsa/verify_witness.h
gf2k/lch14_reed_solomon.h gf2k/lch14.h proto/circuit.h
random/secure_random_engine.h random/transcript.h zk/zk_proof.h
ligero/ligero_param.h merkle/merkle_commitment.h merkle/merkle_tree.h
zk/zk_common.h arrays/eq.h sumcheck/transcript_sumcheck.h
zk/zk_prover.h ligero/ligero_prover.h ligero/ligero_transcript.h
sumcheck/prover_layers.h zk/zk_verifier.h ligero/ligero_verifier.h

EOF

[ "$1" == "clean" ] && {
  for i in ${sources[@]}; do
    rm -f src/$i
  done
  for i in ${headers[@]}; do
    rm -f src/$i
  done
  exit 0
}

[ "$1" == "" ] && {
	>&2 echo "usage: $0 path/to/longfellow-zk"
	exit 1
}

[ -d "$1/lib/ligero" ] || {
	>&2 echo "not found: $1"
	exit 1
}

cd $1 && git pull --rebase && cd -

echo "SOURCES := \\" > src/sources.mk
for i in ${sources[@]}; do
	mkdir -p src/`dirname $i`
	cc="${1}/lib/${i}"
	h="${cc%.cc}.h"
	cp "$cc" src/"$i"
	[ -r "$h" ] && cp "$h" "src/${i%.cc}.h"
	echo "${i}.o \\" >> src/sources.mk
done
echo "src/util/sha256.cc.o    \\" >> sources.mk
echo "src/util/aes_ecb.cc.o    \\" >> sources.mk
# echo "util/randombytes.cc.o \\" >> sources.mk

echo >> sources.mk

for i in ${headers[@]}; do
	mkdir -p src/`dirname $i`
	h="${1}/lib/${i}"
	cp "$h" src/"$i"
done

>&2 echo "🌉 Upstream source imported from $1"
exit 0
