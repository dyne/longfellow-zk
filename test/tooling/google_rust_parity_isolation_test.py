#!/usr/bin/env python3
"""Static contract for keeping the Google/Rust parity harness opt-in."""
from __future__ import annotations
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> None:
    cmake = (ROOT / "CMakeLists.txt").read_text()
    makefile = (ROOT / "GNUmakefile").read_text()
    package_manifests = "\n".join((ROOT / path).read_text() for path in (
        "cmake/manifests/longfellow-zk-sources.cmake",
        "cmake/manifests/longfellow-zk-public-headers.cmake",
        "cmake/manifests/longfellow-zk-boundary.cmake",
    ))

    option = re.search(
        r"option\(LONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY\s+[^\n]+\s+(OFF)\)", cmake
    )
    assert option, "parity CMake option must default OFF"
    guarded = re.search(
        r"if\(LONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY\)(.*?)\nendif\(\)", cmake, re.S
    )
    assert guarded and "add_executable(longfellow-zk-google-cpp-oracle EXCLUDE_FROM_ALL" in guarded.group(1)
    assert "install(" not in guarded.group(1) and "export(" not in guarded.group(1)
    assert "google-rust-parity:" in makefile and "qualification-matrix:" in makefile
    assert "google-rust-parity" not in makefile.split("qualification-matrix:", 1)[1].split("\n\n", 1)[0]
    assert "google-rust-parity" not in package_manifests and "test/google_rust_parity" not in package_manifests
    result = subprocess.run(["make", "help"], cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0 and "opt-in pinned Google C++/Rust parity harness" in result.stdout
    print("google rust parity isolation: default CMake/install/export and qualification boundaries remain opt-in")


if __name__ == "__main__":
    main()
