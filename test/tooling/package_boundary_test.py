#!/usr/bin/env python3
"""Deterministically validate the pre-CMake package boundary manifests."""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "cmake/manifests/longfellow-zk-boundary.cmake"

def cmake_list(name: str) -> list[str]:
    text = MANIFEST.read_text()
    match = re.search(rf"set\({name}\s*(.*?)\n\)", text, re.S)
    if not match:
        raise AssertionError(f"missing {name}")
    return re.findall(r"^\s*((?:src|projects)/[^\s)]+)\s*$", match.group(1), re.M)

def tracked_production() -> set[str]:
    roots = (ROOT / "src", ROOT / "projects")
    return {path.relative_to(ROOT).as_posix()
            for root in roots if root.exists()
            for path in root.rglob("*")
            if path.is_file() and path.suffix in {".cc", ".h"}
            and (root.name == "src" or "/tests/" not in path.relative_to(ROOT).as_posix())}

def assert_unique(label: str, paths: list[str]) -> None:
    duplicate = sorted({path for path in paths if paths.count(path) > 1})
    assert not duplicate, f"duplicate {label} entries: {duplicate}"
    absent = sorted(path for path in paths if not (ROOT / path).is_file())
    assert not absent, f"missing {label} files: {absent}"

def main() -> None:
    groups = [
        cmake_list("LONGFELLOW_ZK_BASE_SOURCES"),
        cmake_list("LONGFELLOW_ZK_NAMED_PROJECT_SOURCES"),
        cmake_list("LONGFELLOW_ZK_PRIVATE_TOOLING_SOURCES"),
        cmake_list("LONGFELLOW_ZK_BASE_HEADERS"),
        cmake_list("LONGFELLOW_ZK_NAMED_PROJECT_HEADERS"),
        cmake_list("LONGFELLOW_ZK_PRIVATE_TOOLING_HEADERS"),
    ]
    for index, paths in enumerate(groups):
        assert_unique(f"ownership group {index}", paths)
    owned = [path for group in groups for path in group]
    assert len(owned) == len(set(owned)), "a production file has multiple owners"
    assert set(owned) == tracked_production(), "manifest does not exhaust tracked production files"

    base = set(groups[0] + groups[3])
    banned = re.compile(r'^#include "circuits/(?:mdoc|ecdsa|bip340)/')
    offenders = []
    for path in sorted(base):
        offenders.extend(f"{path}:{line}" for line in (ROOT / path).read_text().splitlines()
                         if banned.match(line))
    assert not offenders, "base imports named project paths: " + "; ".join(offenders)
    print(f"package boundary inventory: {len(owned)} production files, {len(base)} base files")

if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
