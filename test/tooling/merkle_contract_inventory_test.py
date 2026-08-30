#!/usr/bin/env python3
"""Qualification guard for the native Merkle ownership boundary."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
EUROPEAN = ROOT / "src" / "merkle"
GOOGLE = WORKSPACE / "google-longfellow-zk" / "lib" / "merkle"
GOOGLE_BUILD = WORKSPACE / "google-longfellow-zk" / "build-l4"

HEADERS = ("merkle_tree.h", "merkle_commitment.h")

FIXTURE = r'''
#include <cstdio>
#include <vector>
#include "merkle/merkle_tree.h"

int main() {
  proofs::MerkleTree tree(4);
  for (size_t leaf = 0; leaf != 4; ++leaf) {
    proofs::Digest digest{};
    for (size_t byte = 0; byte != proofs::Digest::kLength; ++byte)
      digest.data[byte] = static_cast<unsigned char>(leaf * 32 + byte);
    tree.set_leaf(leaf, digest);
  }
  const proofs::Digest root = tree.build_tree();
  const size_t position[] = {2};
  std::vector<proofs::Digest> proof;
  tree.generate_compressed_proof(proof, position, 1);
  proofs::Digest leaf{};
  for (size_t byte = 0; byte != proofs::Digest::kLength; ++byte)
    leaf.data[byte] = static_cast<unsigned char>(64 + byte);
  if (!proofs::MerkleTreeVerifier(4, root).verify_compressed_proof(
          proof.data(), proof.size(), &leaf, position, 1)) return 2;
  for (const auto& digest : std::vector<proofs::Digest>{root})
    for (unsigned char byte : digest.data) std::printf("%02x", byte);
  std::printf("\n");
  for (const auto& digest : proof) {
    for (unsigned char byte : digest.data) std::printf("%02x", byte);
    std::printf("\n");
  }
}
'''

PROBE = r'''
#include "merkle/merkle_commitment.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
int main() { proofs::MerkleTree tree(2); (void)tree; }
'''


def run(command: list[str], cwd: Path) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True,
                                   stderr=subprocess.STDOUT)


def compile_fixture(include: Path, library: Path, name: str) -> str:
    with tempfile.TemporaryDirectory(prefix="merkle-parity-") as directory:
        directory_path = Path(directory)
        source = directory_path / "fixture.cc"
        binary = directory_path / name
        source.write_text(FIXTURE, encoding="utf-8")
        run(["ccache", "c++", "-std=c++20", f"-I{include}", str(source),
             str(library), "-lcrypto", "-o", str(binary)], directory_path)
        return run([str(binary)], directory_path)


def installed_probe(prefix: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="merkle-installed-probe-") as directory:
        directory_path = Path(directory)
        (directory_path / "main.cc").write_text(PROBE, encoding="utf-8")
        (directory_path / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.20)\n"
            "project(merkle_installed_probe LANGUAGES CXX)\n"
            "find_package(LongfellowZK CONFIG REQUIRED)\n"
            "add_executable(merkle_installed_probe main.cc)\n"
            "target_link_libraries(merkle_installed_probe PRIVATE LongfellowZK::static)\n",
            encoding="utf-8")
        build = directory_path / "build"
        run(["cmake", "-S", str(directory_path), "-B", str(build), "-G", "Ninja",
             f"-DCMAKE_PREFIX_PATH={prefix}",
             "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache"], directory_path)
        run(["cmake", "--build", str(build)], directory_path)


def source_audit() -> None:
    immutable = {header: (EUROPEAN / header).read_bytes() for header in HEADERS}
    assert all(immutable[header] == (GOOGLE / header).read_bytes()
               for header in HEADERS), "European and Google native headers diverged"
    source_files = [path for path in (ROOT / "src").rglob("*")
                    if path.is_file() and path.suffix in {".cc", ".h"}
                    and path.parent != EUROPEAN]
    forbidden = ("class MerkleTree", "class MerkleTreeVerifier",
                 "compressed_merkle_proof_tree", "struct Digest {")
    offenders = [str(path.relative_to(ROOT)) for path in source_files
                 if any(token in path.read_text(errors="ignore") for token in forbidden)]
    assert not offenders, "second host tree/path algorithm: " + ", ".join(offenders)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-prefix", type=Path,
                        default=WORKSPACE / ".longfellow-install")
    args = parser.parse_args()
    assert shutil.which("ccache"), "ccache is required for C++ probes"
    source_audit()
    european = compile_fixture(args.install_prefix / "include" / "longfellow-zk",
                               args.install_prefix / "lib" / "liblongfellow-zk.a",
                               "european")
    google = compile_fixture(WORKSPACE / "google-longfellow-zk" / "lib",
                             GOOGLE_BUILD / "liblongfellow-zk.a", "google")
    assert european == google, "native root/proof fixture differs from Google"
    installed_probe(args.install_prefix)
    print("merkle ownership: headers, root/proof fixture, and installed probe match")


if __name__ == "__main__":
    main()
