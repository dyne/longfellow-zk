WASI_SDK_PATH := /opt/wasi-sdk
INCLUDES := -I. -I..

posix: CFLAGS := -O3 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
posix:
	$(info 🌉 Building for $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CFLAGS)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="-mpclmul -std=c++17 $(CFLAGS) $(INCLUDES) -I../vendor/zstd/lib"
	@$(MAKE) -C src/cli CXXFLAGS="-std=c++17 $(CFLAGS) $(INCLUDES)" LDADD="$(CURDIR)/src/liblongfellow-zk.a $(CURDIR)/vendor/zstd/lib/libzstd.a"

ccache:
	$(MAKE) posix CXX="ccache $(CXX)" CC="ccache $(CC)"

wasm: CXX := /opt/wasi-sdk/bin/clang++
wasm: CC := /opt/wasi-sdk/bin/clang
wasm: CXXFLAGS := -O3 --sysroot=$(WASI_SDK_PATH)/share/wasi-sysroot -D__wasi__ -fno-exceptions -fno-rtti
wasm:
	$(info 🌉 Building fox $@)
	@$(MAKE) -C vendor/zstd/lib libzstd.a ZSTD_LIB_DICTBUILDER=0 ZSTD_LEGACY_SUPPORT=0 CFLAGS="$(CXXFLAGS)" CC="$(CC)" VERBOSE=1
	@$(MAKE) -C src CXXFLAGS="-nostdlib -msimd128 $(CXXFLAGS) $(INCLUDES) -I../vendor/zstd/lib" CXX="$(CXX)"
	/opt/wasi-sdk/bin/llvm-ranlib src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a
	/opt/wasi-sdk/bin/clang++ ${CXXFLAGS} --target=wasm32-wasi --sysroot=/opt/wasi-sdk/share/wasi-sysroot \
		-Wl,--no-entry -nostartfiles \
		-Wl,--export=run_mdoc_prover -Wl,--export=run_mdoc_verifier \
		-Wl,--export=find_zk_spec \
    -o longfellow-zk.wasm src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

# /opt/wasi-sdk/bin/wasm-ld -o longfellow-zk.wasm --no-entry --strip-all --export-dynamic --allow-undefined \
# 	-L/opt/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasi -lc -lc++ -lc++abi \
#   -L/opt/wasi-sdk/lib/clang/20/lib/wasm32-unknown-wasi/libclang_rt.builtins.a \
# 	--initial-memory=131072 --error-limit=0 --lto-O3 -O3 --gc-sections \
# 	--export=run_mdoc_prover --export=run_mdoc_verifier \
# 	src/liblongfellow-zk.a vendor/zstd/lib/libzstd.a

import-vendor:
	$(info 🌉 Importing source from upstream)
	@bash scripts/import_upstream.sh vendor/longfellow-zk

clean-vendor: clean
	$(info 🌉 Clean up build and all imported vendor sources)
	@bash scripts/import_upstream.sh clean
	@$(MAKE) -C vendor/zstd clean

clean:
	rm -f *.a
	rm -f longfellow-zk longfellow-zk.wasm
	@$(MAKE) -C src clean
	@$(MAKE) -C vendor/zstd clean
