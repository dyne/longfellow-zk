# Profiling

The opt-in profiling target runs five iterations of the end-to-end BIP-340
circuit-build, proof, and verification workload under GNU `gprof`. It builds
the library and its template-heavy caller with instrumentation, while leaving
normal builds unchanged.

Configure an optimized build with debug symbols and build the report target:

```sh
cmake -S . -B build-profile -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DLONGFELLOW_ZK_BUILD_TESTING=OFF \
  -DLONGFELLOW_ZK_BUILD_PROFILING=ON
cmake --build build-profile --target longfellow-zk-profile
```

The flat profile and call graph are written to
`build-profile/profile/gprof.txt`. The raw `gmon.out` is retained alongside it,
and phase metrics are written to `build-profile/results/native_bip340_metrics.csv`.

When Linux `perf` is installed, CMake also exposes a sampling target:

```sh
cmake --build build-profile --target longfellow-zk-profile-perf
```

This writes `perf.data` and a text report to `build-profile/profile/`. If the
target reports a permissions error, an administrator must lower
`/proc/sys/kernel/perf_event_paranoid` or grant the process the appropriate
performance-monitoring capability. The sampling target uses a separate binary
without `gprof` call instrumentation, so its timings are not distorted by
`mcount` hooks.

Use an otherwise idle machine and repeat measurements before accepting small
changes. `gprof` is intended here as a portable first-pass hotspot locator; use
`perf record` or a platform profiler for hardware-counter and cache analysis
when those tools are available.
