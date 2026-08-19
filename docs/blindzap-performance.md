# BlindZap v1 batch limits

The native v1 circuit family supports at most 16 public claims and two
distinct witness programs. Claims sharing a program reuse one ownership
relation; claims with more than two distinct programs are rejected before
circuit allocation. Four relations were measured to exceed Longfellow's CRT
block-encoding guard, so they are deliberately unsupported.

The real native regression (`test/blindzap/blindzap_test`) completed in
4:14.15 with a 1,719,100 KiB peak resident set on the recorded environment.
It exercises the actual proof/verify path and writes circuit/proof metrics to
`test/results/native_blindzap_metrics.csv`. Operators should batch no more
than two distinct programs per proof and use separate proofs for larger sets.
The bounded envelope parser accepts proof payloads up to 128 MiB, which covers
the measured two-key proof while retaining a hard allocation ceiling.
