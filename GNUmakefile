# Transitional compatibility front-end.  CMake presets own all source lists,
# compiler flags, link steps, installation and test registration.
.DEFAULT_GOAL := all

.PHONY: all build test install package clean debug sanitizers wasm posix osx-arm64 qualification-matrix help

all build posix:
	cmake --preset release
	cmake --build --preset release --parallel

debug:
	cmake --preset debug
	cmake --build --preset debug --parallel

sanitizers:
	cmake --preset sanitizers
	cmake --build --preset sanitizers --parallel
	ctest --preset sanitizers

test:
	cmake --preset release
	cmake --build --preset release --parallel
	ctest --preset release

install:
	cmake --install build/release

package:
	cmake --preset release
	cmake --build --preset release --target package --parallel

wasm:
	cmake --preset wasi
	cmake --build --preset wasi --parallel

osx-arm64:
	@echo "Use cmake --preset release on macOS; architecture selection belongs to the CMake toolchain."
	@false

qualification-matrix:
	bash scripts/ci-installed-package.sh

clean:
	cmake -E rm -rf build

help:
	@echo "Deprecated Make compatibility front-end: use cmake --preset <release|debug|sanitizers|wasi>."
