#!/usr/bin/env python3
"""Check source/header package manifests without requiring a CMake build yet."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BOUNDARY = ROOT / "cmake/manifests/longfellow-zk-boundary.cmake"
SOURCES = ROOT / "cmake/manifests/longfellow-zk-sources.cmake"
HEADERS = ROOT / "cmake/manifests/longfellow-zk-public-headers.cmake"

def list_for(name: str) -> list[str]:
    text = BOUNDARY.read_text()
    match = re.search(rf"set\({name}\s*(.*?)\n\)", text, re.S)
    assert match, f"missing {name}"
    return re.findall(r"^\s*(src/[^\s)]+)\s*$", match.group(1), re.M)

def quoted_includes(path: pathlib.Path) -> list[str]:
    return re.findall(r'^\s*#include "([^"]+)"', path.read_text(), re.M)

def main() -> None:
    base_sources = list_for("LONGFELLOW_ZK_BASE_SOURCES")
    base_headers = list_for("LONGFELLOW_ZK_BASE_HEADERS")
    assert SOURCES.read_text().strip().endswith(
        "set(LONGFELLOW_ZK_SOURCES ${LONGFELLOW_ZK_BASE_SOURCES})"
    ), "source manifest must consume only base-owned sources"
    assert HEADERS.read_text().strip().endswith(
        "set(LONGFELLOW_ZK_PUBLIC_HEADERS ${LONGFELLOW_ZK_BASE_HEADERS})"
    ), "public manifest must consume only base-owned headers"
    assert len(base_sources) == len(set(base_sources))
    assert len(base_headers) == len(set(base_headers))
    assert all(path.startswith("src/") and (ROOT / path).is_file()
               for path in base_sources + base_headers)

    public = {path.removeprefix("src/") for path in base_headers}
    missing = []
    pending = list(public)
    visited = set()
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        visited.add(relative)
        source = ROOT / "src" / relative
        for include in quoted_includes(source):
            candidate = ROOT / "src" / include
            if not candidate.is_file():
                continue  # local test fixtures and generated headers are not public dependencies.
            if include not in public:
                missing.append(f"{relative} -> {include}")
            else:
                pending.append(include)
    assert not missing, "public header closure is incomplete: " + "; ".join(sorted(missing))
    forbidden = [path for path in public if path.startswith(("blindzap/", "cli/", "circuits/mdoc/", "circuits/ecdsa/", "circuits/bip340/", "circuits/blindzap/", "circuits/tests/"))]
    assert not forbidden, f"named/private headers leaked into public manifest: {forbidden}"
    print(f"package manifests: {len(base_sources)} sources, {len(public)} public headers, closure complete")

if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
