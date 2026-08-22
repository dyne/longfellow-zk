# LFC2 circuit storage

LFC2 is a compact, canonical storage format for the existing `Circuit`
object.  It does not change circuit arithmetic, canonical circuit IDs,
transcripts, or proof bytes.  LFC1 remains the default writer format and is
always accepted by the reader.

An LFC2 record starts with the four bytes `4c 46 43 32` (`LFC2`).  The header
values follow immediately, in order: field ID, `nv`, `nc`, public-input
count, subfield boundary, input count, layer count, and constant count.
They use minimally encoded unsigned LEB128 varints.  Constants are fixed
width canonical field encodings.  Each layer stores `logw`, wire count, a
deduplicated zig-zag delta table, a segment dictionary, and segment tokens.
The record ends with the unchanged
32-byte canonical circuit ID.

Constants and terms are emitted in the existing `Quad` traversal order.  A
reader reconstructs the same compact delta-table representation, so normal
evaluation continues to traverse compact terms without materializing an
expanded `EQuad`.

All LFC1 dimensional and resource limits apply to LFC2: at most 10,000
layers, 5,000,000 wires/constants, 20,000,000 terms in a layer and in total,
and the configured `ByteCursor` byte/allocation/element limits.  The reader
rejects truncated data, a bad magic, non-minimal or overflowing
varints, delta underflow/overflow, invalid indices, noncanonical field
elements, invalid dimensions, ID mismatches, and trailing bytes.

Operators opt in by passing `CircuitFormat::kLfc2` to `CircuitWriter`; the
default is `kLfc1`.  The magic is sufficient to identify files for metrics or
rollback.  Reverting that selection writes LFC1 again; no circuit conversion,
proof conversion, or historical artifact migration is needed.
