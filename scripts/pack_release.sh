#!/bin/sh

set -e

# setup
TAG="$1"
DST="longfellow-zk_${TAG}"

# create and copy inside
mkdir -p ${DST}
[[ -r longfellow-zk ]] && cp longfellow-zk ${DST}/
[[ -r longfellow-zk.wasm ]] && cp longfellow-zk.wasm ${DST}/
[[ -r src/liblongfellow-zk.a ]] && cp src/liblongfellow-zk.a ${DST}/
cp README.md ${DST}/
cp -r test   ${DST}/
cat <<EOF >  ${DST}/GNUmakefile
all:
	$(info Running Longfellow-zk tests)
	cd test && ./bats/bin/bats .

clean:
	cd test && rm -f circuit*.json proof*.json
EOF

# cleanup test
cd ${DST}/test
make clean
rm -f GNUmakefile extract* circuit*.json proof*.json
cd -

# zip it
zip -r longfellow-zk_${TAG}.zip ${DST}
