CFLAGS ?= -O3 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
WASI_SDK_PATH := /opt/wasi-sdk
INCLUDES := -I. -I..

posix: ARCHFLAGS := -mpclmul
posix:
	$(info 🌉 Building for $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CFLAGS)" CC="$(CC)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="$(ARCHFLAGS) -std=c++17 $(CFLAGS) $(INCLUDES) -I../vendor/zstd/lib"
	@$(MAKE) -C src/cli CXXFLAGS="-std=c++17 $(CFLAGS) $(INCLUDES)" LDADD="$(CURDIR)/src/liblongfellow-zk.a $(CURDIR)/vendor/zstd/lib/libzstd.a"

osx-arm64: ARCHFLAGS := -arch arm64 -march=armv8.1-a+crypto
osx-arm64:
	$(info 🌉 Building for $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CFLAGS)" CC="$(CC)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="$(ARCHFLAGS) -std=c++17 $(CFLAGS) $(INCLUDES) -I../vendor/zstd/lib"
	@$(MAKE) -C src/cli CXXFLAGS="-std=c++17 $(CFLAGS) $(INCLUDES)" LDADD="$(CURDIR)/src/liblongfellow-zk.a $(CURDIR)/vendor/zstd/lib/libzstd.a"

osx-x86: ARCHFLAGS := -arch x86_64 -mpclmul
osx-x86:
	$(info 🌉 Building for $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CFLAGS)" CC="$(CC)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="$(ARCHFLAGS) -std=c++17 $(CFLAGS) $(INCLUDES) -I../vendor/zstd/lib"
	@$(MAKE) -C src/cli CXXFLAGS="-std=c++17 $(CFLAGS) $(INCLUDES)" LDADD="$(CURDIR)/src/liblongfellow-zk.a $(CURDIR)/vendor/zstd/lib/libzstd.a"

wasm: CXX := /opt/wasi-sdk/bin/clang++
wasm: CC := /opt/wasi-sdk/bin/clang
wasm: CXXFLAGS := -O3 --sysroot=$(WASI_SDK_PATH)/share/wasi-sysroot -D__wasi__ -fno-exceptions -fno-rtti
wasm:
	$(info 🌉 Building for $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CXXFLAGS)" CC="$(CC)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="-nostdlib -msimd128 $(CXXFLAGS) $(INCLUDES) -I../vendor/zstd/lib" CXX="$(CXX)"
	/opt/wasi-sdk/bin/llvm-ranlib src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	$(CXX) -msimd128 ${CXXFLAGS} -Isrc -c -o src/cli/wasm.o src/cli/wasm.cc
	/opt/wasi-sdk/bin/clang++ -msimd128 ${CXXFLAGS} --target=wasm32-wasi --sysroot=/opt/wasi-sdk/share/wasi-sysroot \
		-Wl,--no-entry -nostartfiles \
		-Wl,--initial-memory=536870912 -Wl,--max-memory=4294967296 -Wl,--stack-first -Wl,-z,stack-size=16777216 \
		-Wl,--export=wasm_generate_circuit \
		-Wl,--export=malloc \
		-Wl,--export=free \
		-Wl,--export=longfellow_zk_generate_circuit_tobuf \
		-Wl,--export=longfellow_zk_generate_proof_tobuf \
		-Wl,--export=longfellow_zk_verify_proof_tobuf \
		-Wl,--export=longfellow_zk_bip340_smoke_tobuf \
    -o longfellow-zk.wasm src/cli/wasm.o \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

# /opt/wasi-sdk/bin/wasm-ld -o longfellow-zk.wasm --no-entry --strip-all --export-dynamic --allow-undefined \
# 	-L/opt/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasi -lc -lc++ -lc++abi \
#   -L/opt/wasi-sdk/lib/clang/20/lib/wasm32-unknown-wasi/libclang_rt.builtins.a \
# 	--initial-memory=131072 --error-limit=0 --lto-O3 -O3 --gc-sections \
# 	--export=run_mdoc_prover --export=run_mdoc_verifier \
# 	src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

import-vendor:
	$(info 🌉 Importing source from upstream)
	@bash scripts/import_upstream.sh vendor/longfellow-zk

BIP340_UPSTREAM ?= vendor/longfellow-zk
.PHONY: import-bip340
import-bip340:
	$(info 🌉 Importing BIP-340 from $(BIP340_UPSTREAM))
	@bash scripts/import_upstream.sh bip340 "$(BIP340_UPSTREAM)"

.PHONY: bip340-test
bip340-test: test/bip340_test
	@./test/bip340_test

.PHONY: secp256k1-ec-gadget-test
secp256k1-ec-gadget-test: test/secp256k1/ec_gadget_test
	@./test/secp256k1/ec_gadget_test

.PHONY: blindzap-spec-test
blindzap-spec-test:
	@python3 scripts/check_blindzap_spec.py
	@python3 scripts/generate_blindzap_vectors.py | cmp -s - test/blindzap/testdata/blindzap_vectors.json

BIP340_DEPS := $(wildcard src/circuits/bip340/*.h) \
	$(wildcard src/circuits/secp256k1/*.h) \
	$(wildcard test/bip340/testdata/*)

src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a:
	@$(MAKE) posix

test/bip340_test: test/bip340/bip340_test.cc $(BIP340_DEPS) \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Itest/bip340 -Ivendor/zstd/lib -o $@ $< \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/secp256k1/ec_gadget_test: test/secp256k1/ec_gadget_test.cc $(wildcard src/circuits/secp256k1/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/secp256k1
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

clean-vendor: clean
	$(info 🌉 Clean up build and all imported vendor sources)
	@bash scripts/import_upstream.sh clean
	@$(MAKE) -C vendor/zstd clean

clean:
	rm -f *.a
	rm -f longfellow-zk longfellow-zk.wasm
	rm -f test/bip340_test
	@$(MAKE) -C src clean
	@$(MAKE) -C vendor/zstd clean
