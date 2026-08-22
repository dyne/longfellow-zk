# Longfellow-ZK external Rust interop adapter

This directory is first-party integration code, not a copy or fork of
`vendor/longfellow-zk`.  Its Cargo path dependencies intentionally point at
the read-only Google upstream submodule.

`cargo run --manifest-path vendor/longfellow-zk-interop/Cargo.toml -- --cpp CPP.lfc2 --rust RUST.lfc2`
strictly reads the canonical C++ P-256 LFC2 fixture, checks the canonical ID
and that no bytes remain, then writes the canonical Rust LFC2 fixture.  The
C++ harness reads that output as the reciprocal half of the test.

Do not add test hooks, commits, or local patches under `vendor/longfellow-zk`.
If a local checkout still points at a detached unpublished object, restore the
parent gitlink to its published Google revision and initialize the submodule:

```sh
git submodule update --init --recursive vendor/longfellow-zk
```

The adapter builds into its own `target/` directory; pre-existing untracked
`vendor/longfellow-zk/rust/target/` content is intentionally untouched.
