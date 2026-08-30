#!/usr/bin/env python3
import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "cmake/manifests/longfellow-zk-test-ownership.cmake"

def main():
    entries = re.findall(r'"([^"|]+)\|([^"|]+)\|([^"|]+)"', MANIFEST.read_text())
    paths = [entry[0] for entry in entries]
    assert len(paths) == len(set(paths)), "duplicate test ownership"
    assert all((ROOT / path).is_file() for path in paths), "missing owned test asset"
    assert all(owner in {"base", "bip340", "ecdsa", "mdoc"} and target
               for _, owner, target in entries), "invalid owner or replacement target"
    tracked = subprocess.check_output(["git", "ls-files", "scripts", "test", "spec"],
                                      cwd=ROOT, text=True).splitlines()
    project_tests = [path.relative_to(ROOT).as_posix()
                     for path in (ROOT / "projects").glob("*/tests/**/*")
                     if path.is_file()]
    project_scripts = [path.relative_to(ROOT).as_posix()
                       for path in (ROOT / "projects").glob("*/scripts/*")
                       if path.is_file()]
    project_specs = [path.relative_to(ROOT).as_posix()
                     for path in (ROOT / "projects").glob("*/spec/**/*")
                     if path.is_file() and path.suffix == ".sage"]
    # Bats and bats-assert are vendored generic runners; result logs are outputs,
    # and the specification README is documentation rather than a test asset.
    exclusions = ("test/bats/", "test/test_helper/", "test/results/", "test/bats_setup",
                  "test/cmake/", "test/tooling/test_ownership_manifest_test.py")
    eligible = {path for path in tracked if (ROOT / path).is_file()
                and not path.startswith(exclusions)} | set(project_tests) | set(project_scripts) | set(project_specs)
    owned = set(paths)
    # During this uncommitted migration the two package inventory tests are
    # deliberately already owned; once committed they join `eligible` above.
    pending_inventory_tests = {
        "test/tooling/package_boundary_test.py",
        "test/tooling/package_manifest_test.py",
        "test/tooling/merkle_contract_inventory_test.py",
        "test/tooling/merkle_membership_contract_test.py",
        "test/tooling/merkle_parity_qualification_test.py",
        "test/merkle/canonical_merkle_membership_vector.schema.json",
        "test/merkle/canonical_merkle_membership_vectors.json",
        "test/cbor/host_decoder_test.cc",
        "test/cbor/cbor_byte_decoder_test.cc",
    }
    assert owned - eligible <= pending_inventory_tests, f"stale={sorted(owned - eligible)}"
    assert eligible <= owned, f"missing={sorted(eligible - owned)}"
    print(f"test ownership: {len(entries)} eligible assets, {len(set(owner for _, owner, _ in entries))} owners")

if __name__ == "__main__":
    try: main()
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr); raise SystemExit(1)
