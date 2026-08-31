#!/usr/bin/env python3
"""Keep the optional Google Rust parity guide aligned with its public contract."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs/google-rust-parity.md"
SCRIPT = ROOT / "scripts/google_rust_parity.sh"


def main():
    guide = GUIDE.read_text()
    script = SCRIPT.read_text()
    required = (
        "make google-rust-parity",
        "GOOGLE_RUST_PARITY_BUILD_DIR",
        "GOOGLE_RUST_PARITY_CARGO_TARGET_DIR",
        "vendor/longfellow-zk",
        "https://github.com/google/longfellow-zk",
        "ccache",
        "git submodule update --init -- vendor/longfellow-zk",
        "qualification-matrix",
    )
    assert all(token in guide for token in required), "parity guide misses a public contract token"
    assert "LONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY=ON" in script
    assert "CMAKE_CXX_COMPILER_LAUNCHER=ccache" in script
    assert "C++ launcher=none (ccache unavailable)" in script
    print("google rust parity docs: invocation, pinning, isolation, and ccache fallback documented")


if __name__ == "__main__":
    main()
