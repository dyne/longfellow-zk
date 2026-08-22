# C++20 migration measurements

The C++20 boundary migration is accepted only when the following reproducible
commands complete without protocol-vector drift:

```sh
/usr/bin/time -f 'elapsed=%e maxrss_kib=%M' make -B cpp20-contract-test CXX=g++
stat -c '%n %s' longfellow-zk longfellow-zk.wasm src/liblongfellow-zk.a
make compatibility-vectors-test
```

Recorded baseline commit: `ac7f1b8af866de071686fb4a20373979241e8e00`.
Host: Linux 6.12.95+deb13-amd64 x86_64; compiler: GCC 14.2.0.  The representative
workload is a clean `make -B cpp20-contract-test CXX=g++`, repeated twice:
0.15s/45,592KiB and 0.15s/45,776KiB (range 0.00s, 184KiB).  Before changes the
native executable was 2,508,816 bytes and WASM was 3,172,292 bytes.  Current
native/static archive values are 2,492,008/1,466,924 bytes.

The local WASM artifact is absent after the pre-existing mixed host/WASI archive
rebuild sequence, so no after-WASM size or before/after claim is made.  A clean
WASI rebuild is required before accepting the 1% size budget.  Budget: no
serialization-vector change; contract-test elapsed time is not more than 10%
above the recorded baseline on the same host; native, static archive, and WASM
growth over 1% requires review. Concepts and explicit template instantiation
are deferred pending a measured repeated-instantiation hotspot; no lack-of-
hotspot claim is made here.

`ByteCursor::position()` remains source-compatible and returns `size_t`; new
parser internals use the explicit `ByteOffset` accessor where needed.
