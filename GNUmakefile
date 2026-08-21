CFLAGS ?= -O3 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
SANITIZER_CC ?= clang
SANITIZER_CXX ?= clang++
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
	@python3 scripts/generate_blindzap_vectors.py | diff -u test/blindzap/testdata/blindzap_vectors.json -

.PHONY: blindzap-sage-test
blindzap-sage-test:
	@./scripts/run_blindzap_sage.sh

.PHONY: blindzap-sage-vector-test
blindzap-sage-vector-test: test/blindzap/sage_vector_test
	@./test/blindzap/sage_vector_test test/blindzap/testdata/blindzap_sage_vectors.json

.PHONY: blindzap-key-ownership-test
blindzap-key-ownership-test: test/blindzap/key_ownership_test
	@./test/blindzap/key_ownership_test

.PHONY: blindzap-sha256-test
blindzap-sha256-test: test/blindzap/compressed_key_sha256_test
	@./test/blindzap/compressed_key_sha256_test

.PHONY: blindzap-ripemd160-test
blindzap-ripemd160-test: test/blindzap/ripemd160_test
	@./test/blindzap/ripemd160_test

.PHONY: blindzap-test
blindzap-test: test/blindzap/blindzap_test
	@mkdir -p test/results
	@./test/blindzap/blindzap_test

.PHONY: blindzap-protocol-test
blindzap-protocol-test: test/blindzap/protocol_test
	@./test/blindzap/protocol_test

.PHONY: blindzap-integration-test
blindzap-integration-test: test/blindzap/integration_test
	@./test/blindzap/integration_test

.PHONY: blindzap-cli
blindzap-cli: blindzap
	@./test/blindzap/cli_test.sh ./blindzap

.PHONY: blindzap-ci-test dense-test
blindzap-ci-test: panic-parser-test blindzap-spec-test bip340-test secp256k1-ec-gadget-test \
		blindzap-key-ownership-test blindzap-sha256-test \
		blindzap-ripemd160-test blindzap-sage-vector-test blindzap-protocol-test \
		blindzap-integration-test blindzap-cli transcript-clone-test

dense-test: test/arrays/dense_test
	@./test/arrays/dense_test

.PHONY: transcript-clone-test
transcript-clone-test: test/random/transcript_clone_test
	@./test/random/transcript_clone_test

.PHONY: panic-parser-test
panic-parser-test: test/security/panic_parser_test
	@./test/security/panic_parser_test

.PHONY: blindzap-proof-test
blindzap-proof-test: blindzap-test

.PHONY: blindzap-static-analysis
blindzap-static-analysis:
	@./scripts/run_blindzap_static_analysis.sh

# Reviewed compatibility vectors are validation-only by default.  Updating
# them requires spelling out the overwrite acknowledgement at the command
# line, so a normal test run can never rewrite a reviewed baseline.
.PHONY: compatibility-vectors compatibility-vectors-update compatibility-vectors-test \
	baseline-metrics baseline-metrics-test compile-commands baseline-static-analysis \
	baseline-sanitizers parser-fuzz transcript-fuzz fuzz-crash-replay fuzz-smoke
compatibility-vectors:
	@python3 scripts/compatibility_vectors.py --implementation cpp
	@python3 scripts/compatibility_vectors.py --implementation rust

compatibility-vectors-update:
	@python3 scripts/compatibility_vectors.py --update --allow-reviewed-overwrite

compatibility-vectors-test: compatibility-vectors
	@python3 test/compatibility/compatibility_vectors_test.py

# Baseline tooling intentionally writes only generated, ignored artifacts.  The
# checked-in scripts and seed corpora make each measurement and fuzz replay
# command reproducible without changing protocol code.
baseline-metrics:
	@python3 scripts/baseline_metrics.py --runs 3 --output test/results/baseline_metrics.csv

baseline-metrics-test:
	@python3 test/tooling/baseline_tooling_test.py

compile-commands:
	@rm -f compile_commands.json
	@bear --output compile_commands.json -- $(MAKE) -B test/security/panic_parser_test
	@test -s compile_commands.json

baseline-static-analysis:
	@./scripts/run_baseline_static_analysis.sh

baseline-sanitizers:
	@$(MAKE) clean
	@$(MAKE) -j$$(nproc) posix CC=$(SANITIZER_CC) CXX=$(SANITIZER_CXX) CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-strict-overflow"
	@ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(MAKE) panic-parser-test CC=$(SANITIZER_CC) CXX=$(SANITIZER_CXX) CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-strict-overflow"

test/fuzz/parser_fuzz: test/fuzz/parser_fuzz.cc src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/fuzz
	clang++ -std=c++17 -O1 -g -DFUZZ_STANDALONE -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/fuzz/transcript_fuzz: test/fuzz/transcript_fuzz.cc src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/fuzz
	clang++ -std=c++17 -O1 -g -DFUZZ_STANDALONE -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

parser-fuzz: test/fuzz/parser_fuzz
	@./test/fuzz/parser_fuzz test/fuzz/corpus/parser/truncated_lfc1

transcript-fuzz: test/fuzz/transcript_fuzz
	@./test/fuzz/transcript_fuzz test/fuzz/corpus/transcript/empty test/fuzz/corpus/transcript/seed

fuzz-crash-replay:
	@python3 test/fuzz/replay_seeded_crash.py

fuzz-smoke: parser-fuzz transcript-fuzz fuzz-crash-replay

blindzap: src/cli/blindzap_main.cc $(wildcard src/blindzap/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

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

test/security/panic_parser_test: test/security/panic_parser_test.cc \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/security
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/random/transcript_clone_test: test/random/transcript_clone_test.cc \
		src/random/transcript.h src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/random
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/arrays/dense_test: test/arrays/dense_test.cc src/arrays/dense.h \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/arrays
	$(CXX) -std=c++17 $(CFLAGS) -DPROOFS_DENSE_TESTING -Isrc -Ivendor/zstd/lib -o $@ $< \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/key_ownership_test: test/blindzap/key_ownership_test.cc $(wildcard src/circuits/blindzap/*.h) $(wildcard src/circuits/secp256k1/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/compressed_key_sha256_test: test/blindzap/compressed_key_sha256_test.cc $(wildcard src/circuits/blindzap/*.h) $(wildcard src/circuits/secp256k1/*.h) $(wildcard src/circuits/sha/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/ripemd160_test: test/blindzap/ripemd160_test.cc $(wildcard src/circuits/ripemd160/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/sage_vector_test: test/blindzap/sage_vector_test.cc \
		test/blindzap/testdata/blindzap_sage_vectors.json \
		$(wildcard src/blindzap/*.h) $(wildcard src/circuits/blindzap/*.h) \
		$(wildcard src/circuits/ripemd160/*.h) \
		$(wildcard src/circuits/secp256k1/*.h) src/liblongfellow-zk.a \
		vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< \
		src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/blindzap_test: test/blindzap/blindzap_test.cc $(wildcard src/blindzap/*.h) $(wildcard src/circuits/blindzap/*.h) $(wildcard src/circuits/ripemd160/*.h) $(wildcard src/circuits/secp256k1/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/protocol_test: test/blindzap/protocol_test.cc $(wildcard src/blindzap/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

test/blindzap/integration_test: test/blindzap/integration_test.cc $(wildcard src/blindzap/*.h) src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	@mkdir -p test/blindzap
	$(CXX) -std=c++17 $(CFLAGS) -Isrc -Ivendor/zstd/lib -o $@ $< src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

clean-vendor: clean
	$(info 🌉 Clean up build and all imported vendor sources)
	@bash scripts/import_upstream.sh clean
	@$(MAKE) -C vendor/zstd clean

clean:
	rm -f *.a
	rm -f blindzap
	rm -f longfellow-zk longfellow-zk.wasm
	rm -f test/bip340_test
	rm -f test/secp256k1/ec_gadget_test
	rm -f test/security/panic_parser_test
	rm -f test/random/transcript_clone_test
	rm -f test/fuzz/parser_fuzz test/fuzz/transcript_fuzz
	rm -f test/blindzap/blindzap_test
	rm -f test/blindzap/compressed_key_sha256_test
	rm -f test/blindzap/integration_test
	rm -f test/blindzap/key_ownership_test
	rm -f test/blindzap/protocol_test
	rm -f test/blindzap/ripemd160_test
	rm -f test/blindzap/sage_vector_test
	@$(MAKE) -C src clean
	@$(MAKE) -C vendor/zstd clean
