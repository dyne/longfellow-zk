// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_READER_H_
#define PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_READER_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "proto/circuit_io.h"
#include "sumcheck/circuit.h"
#include "sumcheck/circuit_id.h"
#include "sumcheck/quad.h"
#include "sumcheck/quad_builder.h"
#include "util/ceildiv.h"
#include "util/byte_cursor.h"
#include "util/readbuffer.h"

namespace proofs {

enum class CircuitReadErrorCode {
  kNone = 0,
  kTruncated,
  kUnsupportedVersion,
  kWrongField,
  kInvalidDimensions,
  kResourceLimit,
  kNoncanonicalFieldElement,
  kInvalidLayer,
  kInvalidDelta,
  kInvalidIndex,
  kCircuitIdMismatch,
  kTrailingBytes,
};

struct CircuitReadError {
  CircuitReadErrorCode code = CircuitReadErrorCode::kNone;
  size_t offset = 0;
  size_t layer = SIZE_MAX;
  size_t term = SIZE_MAX;

  explicit operator bool() const { return code != CircuitReadErrorCode::kNone; }
};

// Bounded reader for untrusted LFC1 circuit artifacts.  The legacy public
// result remains nullptr-on-error, while last_error() retains structured
// diagnostics for API boundaries that can expose them.

template <class Field>
class CircuitReader {
  using Elt = typename Field::Elt;
  using QuadCorner = typename Quad<Field>::quad_corner_t;

 public:
  explicit CircuitReader(const Field& f, FieldID field_id)
      : f_(f), field_id_(field_id) {}

  const CircuitReadError& last_error() const { return last_error_; }

  // Returns a unique_ptr<Circuit> or nullptr if there is an error in
  // deserializing the circuit.
  //
  // If ENFORCE_CIRCUIT_ID is TRUE, check that the circuit id in
  // the serialization matches the id stored in the circuit.
  std::unique_ptr<Circuit<Field>> from_bytes(ReadBuffer& buf,
                                             bool enforce_circuit_id) {
    ByteCursor cursor(buf.data(), buf.remaining());
    auto result = from_bytes(cursor, enforce_circuit_id);
    if (result) (void)buf.advance(cursor.position());
    return result;
  }

  std::unique_ptr<Circuit<Field>> from_bytes(ByteCursor& buf,
                                             bool enforce_circuit_id) {
    auto result = from_record(buf, enforce_circuit_id);
    if (result && buf.remaining() != 0) {
      return fail(CircuitReadErrorCode::kTrailingBytes, buf);
    }
    return result;
  }

  // Explicit archive-only API: callers reading a concatenation must consume
  // every record and validate end-of-archive themselves.
  std::unique_ptr<Circuit<Field>> from_record(ByteCursor& buf,
                                              bool enforce_circuit_id) {
    last_error_ = {};
    if (buf.have(CircuitIO::kLfc2Magic.size()) &&
        std::memcmp(buf.data(), CircuitIO::kLfc2Magic.data(),
                    CircuitIO::kLfc2Magic.size()) == 0) {
      return from_lfc2_record(buf, enforce_circuit_id);
    }
    if (!buf.have(8 * CircuitIO::kBytesPerSizeT + 1)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }

    const uint8_t* bytes = nullptr;
    if (!buf.take(1, &bytes)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }
    uint8_t version = bytes[0];
    if (version != CircuitIO::kLfc1Version) {
      return fail(CircuitReadErrorCode::kUnsupportedVersion, buf);
    }

    size_t fid_as_size_t, nv, nc, npub_in, subfield_boundary, ninputs, nl,
        numconst;
    if (!read_num(buf, &fid_as_size_t) || !read_num(buf, &nv) ||
        !read_num(buf, &nc) || !read_num(buf, &npub_in) ||
        !read_num(buf, &subfield_boundary) || !read_num(buf, &ninputs) ||
        !read_num(buf, &nl) || !read_num(buf, &numconst)) {
      return fail(buf.error().code == ParseErrorCode::kResourceLimit
                      ? CircuitReadErrorCode::kResourceLimit
                      : CircuitReadErrorCode::kTruncated,
                  buf);
    }

    if (fid_as_size_t != static_cast<size_t>(field_id_)) {
      return fail(CircuitReadErrorCode::kWrongField, buf);
    }
    if (nv == 0 || nc == 0 || ninputs == 0 || nl == 0 || numconst == 0 ||
        npub_in > ninputs || subfield_boundary > ninputs) {
      return fail(CircuitReadErrorCode::kInvalidDimensions, buf);
    }
    if (nv > CircuitIO::kMaxWires || nc > CircuitIO::kMaxWires ||
        ninputs > CircuitIO::kMaxWires || nl > CircuitIO::kMaxLayers ||
        numconst > CircuitIO::kMaxConstants) {
      return fail(CircuitReadErrorCode::kResourceLimit, buf);
    }

    // Ensure there are enough input bytes for the quad constants.
    auto need = CircuitIO::checked_mul(numconst, Field::kBytes);
    if (!need || !buf.have(need.value())) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }

    if (!buf.consume_allocation(numconst) || !buf.consume_elements(numconst)) {
      return fail(CircuitReadErrorCode::kResourceLimit, buf);
    }
    auto constants = std::make_shared<std::vector<Elt>>(numconst);
    for (size_t i = 0; i < numconst; ++i) {
      if (!buf.take(Field::kBytes, &bytes)) {
        return fail(CircuitReadErrorCode::kTruncated, buf);
      }
      auto vv = f_.of_bytes_field(bytes);
      if (!vv.has_value()) {
        return fail(CircuitReadErrorCode::kNoncanonicalFieldElement, buf);
      }
      (*constants)[i] = vv.value();
    }

    auto c = std::make_unique<Circuit<Field>>();
    *c = Circuit<Field>{
        .nv = nv,
        .logv = lg(nv),
        .nc = nc,
        .logc = lg(nc),
        .nl = nl,
        .ninputs = ninputs,
        .npub_in = npub_in,
        .subfield_boundary = subfield_boundary,
    };
    c->l.reserve(nl);

    // a starting bound on quad number
    size_t max_g = nv;

    // Use an approximate delta table builder, preferring quick lookup at the
    // cost of missing some deduplications.
    ApproximateDeltaTableBuilder<Field> db(/*prime*/ 8209);
    size_t total_terms = 0;

    for (size_t ly = 0; ly < nl; ++ly) {
      // Ensure there are enough input bytes for the layer, 3 values.
      if (!buf.have(3 * CircuitIO::kBytesPerSizeT)) {
        return fail(CircuitReadErrorCode::kTruncated, buf, ly);
      }

      size_t lw, nw, nq;
      if (!read_num(buf, &lw) || !read_num(buf, &nw) ||
          !read_num(buf, &nq)) {
        return fail(CircuitReadErrorCode::kTruncated, buf, ly);
      }
      if (lw > LayerProof<Field>::kMaxBindings || nw == 0 || nq == 0 ||
          lw != lg(nw)) {
        return fail(CircuitReadErrorCode::kInvalidLayer, buf, ly);
      }
      if (nw > CircuitIO::kMaxWires ||
          nq > CircuitIO::kMaxTermsPerLayer ||
          total_terms > CircuitIO::kMaxTotalTerms - nq) {
        return fail(CircuitReadErrorCode::kResourceLimit, buf, ly);
      }
      total_terms += nq;

      // Each quad takes 4 values, check for overflow.
      need = CircuitIO::checked_mul(4 * CircuitIO::kBytesPerSizeT, nq);
      if (!need || !buf.have(need.value())) {
        return fail(CircuitReadErrorCode::kTruncated, buf, ly);
      }

      if (!buf.consume_allocation(nq) || !buf.consume_elements(nq)) {
        return fail(CircuitReadErrorCode::kResourceLimit, buf, ly);
      }
      auto qq = std::make_unique<Quad<Field>>(nq, constants, db.delta_table());
      size_t prevg = 0, prevhl = 0, prevhr = 0;
      for (size_t i = 0; i < nq; ++i) {
        size_t g, hl, hr, vi;
        if (!read_index(buf, prevg, &g) || !read_index(buf, prevhl, &hl) ||
            !read_index(buf, prevhr, &hr)) {
          return fail(CircuitReadErrorCode::kInvalidDelta, buf, ly, i);
        }
        if (g >= max_g) {  // index of quad must be < wires in the layer
          return fail(CircuitReadErrorCode::kInvalidIndex, buf, ly, i);
        }
        if (hl >= nw || hr >= nw) {
          return fail(CircuitReadErrorCode::kInvalidIndex, buf, ly, i);
        }
        if (!read_num(buf, &vi)) {
          return fail(CircuitReadErrorCode::kTruncated, buf, ly, i);
        }
        if (vi >= numconst) {
          return fail(CircuitReadErrorCode::kInvalidIndex, buf, ly, i);
        }

        qq->assign(
            i, db.dedup(QuadCorner(static_cast<uint32_t>(g) -
                                   static_cast<uint32_t>(prevg)),
                        QuadCorner(static_cast<uint32_t>(hl) -
                                   static_cast<uint32_t>(prevhl)),
                        QuadCorner(static_cast<uint32_t>(hr) -
                                   static_cast<uint32_t>(prevhr)),
                        static_cast<uint32_t>(vi)));
        prevg = g;
        prevhl = hl;
        prevhr = hr;
      }
      c->l.push_back(Layer<Field>{
          .nw = nw,
          .logw = lw,
          .quad = std::unique_ptr<const Quad<Field>>(std::move(qq))});
      // The outputs of layer ly become the inputs for layer ly+1.
      // Thus, the new maximum value for g in the next layer is the number of
      // wires in this layer.
      max_g = nw;
    }
    if (max_g != ninputs) {
      return fail(CircuitReadErrorCode::kInvalidDimensions, buf);
    }
    // Read the circuit name from the serialization.
    if (!buf.copy(CircuitIO::kIdSize, c->id)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }

    if (enforce_circuit_id) {
      uint8_t idtmp[CircuitIO::kIdSize];
      circuit_id(idtmp, *c, f_);
      if (memcmp(idtmp, c->id, CircuitIO::kIdSize) != 0) {
        return fail(CircuitReadErrorCode::kCircuitIdMismatch, buf);
      }
    }
    return c;
  }

 private:
  // LFC2 is deliberately decoded into the same compact Quad representation as
  // LFC1.  Its only semantic difference is the canonical variable-length
  // storage of header values and term deltas.
  std::unique_ptr<Circuit<Field>> from_lfc2_record(ByteCursor& buf,
                                                    bool enforce_circuit_id) {
    const uint8_t* bytes = nullptr;
    if (!buf.take(CircuitIO::kLfc2Magic.size(), &bytes))
      return fail(CircuitReadErrorCode::kTruncated, buf);

    size_t fid, nv, nc, npub, boundary, ninputs, nl, numconst;
    if (!read_varint(buf, &fid) || !read_varint(buf, &nv) ||
        !read_varint(buf, &nc) || !read_varint(buf, &npub) ||
        !read_varint(buf, &boundary) || !read_varint(buf, &ninputs) ||
        !read_varint(buf, &nl) || !read_varint(buf, &numconst))
      return fail(CircuitReadErrorCode::kInvalidDelta, buf);
    if (fid != static_cast<size_t>(field_id_))
      return fail(CircuitReadErrorCode::kWrongField, buf);
    if (nv == 0 || nc == 0 || ninputs == 0 || nl == 0 || numconst == 0 ||
        npub > ninputs || boundary > ninputs)
      return fail(CircuitReadErrorCode::kInvalidDimensions, buf);
    if (nv > CircuitIO::kMaxWires || nc > CircuitIO::kMaxWires ||
        ninputs > CircuitIO::kMaxWires || nl > CircuitIO::kMaxLayers ||
        numconst > CircuitIO::kMaxConstants)
      return fail(CircuitReadErrorCode::kResourceLimit, buf);
    auto need = CircuitIO::checked_mul(numconst, Field::kBytes);
    if (!need || !buf.have(need.value()))
      return fail(CircuitReadErrorCode::kTruncated, buf);
    if (!buf.consume_allocation(numconst) || !buf.consume_elements(numconst))
      return fail(CircuitReadErrorCode::kResourceLimit, buf);
    auto constants = std::make_shared<std::vector<Elt>>(numconst);
    for (size_t i = 0; i < numconst; ++i) {
      if (!buf.take(Field::kBytes, &bytes))
        return fail(CircuitReadErrorCode::kTruncated, buf);
      auto value = f_.of_bytes_field(bytes);
      if (!value) return fail(CircuitReadErrorCode::kNoncanonicalFieldElement, buf);
      (*constants)[i] = *value;
    }
    auto circuit = std::make_unique<Circuit<Field>>();
    *circuit = Circuit<Field>{.nv = nv, .logv = lg(nv), .nc = nc,
                              .logc = lg(nc), .nl = nl, .ninputs = ninputs,
                              .npub_in = npub, .subfield_boundary = boundary};
    circuit->l.reserve(nl);
    size_t max_g = nv, total_terms = 0;
    ApproximateDeltaTableBuilder<Field> table_builder(/*prime*/ 8209);
    for (size_t layer = 0; layer < nl; ++layer) {
      size_t logw, nw, ndeltas;
      if (!read_varint(buf, &logw) || !read_varint(buf, &nw) ||
          !read_varint(buf, &ndeltas))
        return fail(CircuitReadErrorCode::kTruncated, buf, layer);
      if (logw > LayerProof<Field>::kMaxBindings || nw == 0 || ndeltas == 0 ||
          logw != lg(nw))
        return fail(CircuitReadErrorCode::kInvalidLayer, buf, layer);
      if (nw > CircuitIO::kMaxWires || ndeltas > CircuitIO::kMaxTermsPerLayer)
        return fail(CircuitReadErrorCode::kResourceLimit, buf, layer);
      struct Delta { int32_t g, h0, h1; uint32_t constant; };
      std::vector<Delta> deltas;
      deltas.reserve(ndeltas);
      for (size_t index = 0; index < ndeltas; ++index) {
        size_t g, h0, h1, constant;
        if (!read_varint(buf, &g) || !read_varint(buf, &h0) || !read_varint(buf, &h1) || !read_varint(buf, &constant) || constant >= numconst)
          return fail(CircuitReadErrorCode::kInvalidDelta, buf, layer, index);
        auto unzigzag = [](size_t value) { return static_cast<int32_t>((value >> 1) ^ -static_cast<int32_t>(value & 1)); };
        deltas.push_back({unzigzag(g), unzigzag(h0), unzigzag(h1), static_cast<uint32_t>(constant)});
      }
      size_t nsegments;
      if (!read_varint(buf, &nsegments) || nsegments == 0 || nsegments > CircuitIO::kMaxTermsPerLayer)
        return fail(CircuitReadErrorCode::kInvalidLayer, buf, layer);
      std::vector<std::vector<uint32_t>> segments(nsegments);
      size_t nq = 0;
      for (size_t segment = 0; segment < nsegments; ++segment) {
        size_t length;
        if (!read_varint(buf, &length) || length > CircuitIO::kMaxTermsPerLayer - nq)
          return fail(CircuitReadErrorCode::kResourceLimit, buf, layer);
        nq += length; segments[segment].reserve(length);
        for (size_t item = 0; item < length; ++item) { size_t index; if (!read_varint(buf, &index) || index >= deltas.size()) return fail(CircuitReadErrorCode::kInvalidIndex, buf, layer); segments[segment].push_back(static_cast<uint32_t>(index)); }
      }
      size_t ntokens;
      if (!read_varint(buf, &ntokens) || ntokens == 0 || ntokens > CircuitIO::kMaxTermsPerLayer)
        return fail(CircuitReadErrorCode::kInvalidLayer, buf, layer);
      std::vector<uint32_t> sequence;
      nq = 0;
      for (size_t token = 0; token < ntokens; ++token) { size_t index; if (!read_varint(buf, &index) || index >= segments.size() || segments[index].size() > CircuitIO::kMaxTermsPerLayer - nq) return fail(CircuitReadErrorCode::kInvalidIndex, buf, layer); nq += segments[index].size(); sequence.push_back(static_cast<uint32_t>(index)); }
      if (nq == 0 || total_terms > CircuitIO::kMaxTotalTerms - nq)
        return fail(CircuitReadErrorCode::kResourceLimit, buf, layer);
      total_terms += nq;
      if (!buf.consume_allocation(nq) || !buf.consume_elements(nq))
        return fail(CircuitReadErrorCode::kResourceLimit, buf, layer);
      auto quad = std::make_unique<Quad<Field>>(nq, constants, table_builder.delta_table());
      size_t previous_g = 0, previous_h0 = 0, previous_h1 = 0;
      size_t term = 0;
      for (uint32_t token : sequence) for (uint32_t delta_index : segments[token]) {
        const auto& delta = deltas[delta_index];
        size_t g = static_cast<uint32_t>(static_cast<uint32_t>(previous_g) + static_cast<uint32_t>(delta.g));
        size_t h0 = static_cast<uint32_t>(static_cast<uint32_t>(previous_h0) + static_cast<uint32_t>(delta.h0));
        size_t h1 = static_cast<uint32_t>(static_cast<uint32_t>(previous_h1) + static_cast<uint32_t>(delta.h1));
        size_t constant = delta.constant;
        if (g >= max_g || h0 >= nw || h1 >= nw || constant >= numconst)
          return fail(CircuitReadErrorCode::kInvalidIndex, buf, layer, term);
        quad->assign(term, table_builder.dedup(
            QuadCorner(static_cast<uint32_t>(g - previous_g)),
            QuadCorner(static_cast<uint32_t>(h0 - previous_h0)),
            QuadCorner(static_cast<uint32_t>(h1 - previous_h1)),
            static_cast<uint32_t>(constant)));
        previous_g = g; previous_h0 = h0; previous_h1 = h1;
        ++term;
      }
      circuit->l.push_back({.nw = nw, .logw = logw,
                            .quad = std::unique_ptr<const Quad<Field>>(std::move(quad))});
      max_g = nw;
    }
    if (max_g != ninputs) return fail(CircuitReadErrorCode::kInvalidDimensions, buf);
    if (!buf.copy(CircuitIO::kIdSize, circuit->id))
      return fail(CircuitReadErrorCode::kTruncated, buf);
    if (enforce_circuit_id) {
      uint8_t expected[CircuitIO::kIdSize];
      circuit_id(expected, *circuit, f_);
      if (std::memcmp(expected, circuit->id, CircuitIO::kIdSize) != 0)
        return fail(CircuitReadErrorCode::kCircuitIdMismatch, buf);
    }
    return circuit;
  }

  static bool read_varint(ByteCursor& buf, size_t* out) {
    uint64_t value = 0;
    for (size_t index = 0; index < 10; ++index) {
      const uint8_t* byte = nullptr;
      if (!buf.take(1, &byte)) return false;
      if (index == 9 && (byte[0] & 0xfe) != 0) return false;
      value |= uint64_t(byte[0] & 0x7f) << (7 * index);
      if ((byte[0] & 0x80) == 0) {
        if (index != 0 && (byte[0] & 0x7f) == 0) return false;
        if (value > SIZE_MAX) return false;
        *out = static_cast<size_t>(value);
        return true;
      }
    }
    return false;
  }

  static bool read_delta(ByteCursor& buf, size_t previous, size_t* out) {
    size_t encoded;
    if (!read_varint(buf, &encoded)) return false;
    const size_t magnitude = encoded >> 1;
    if (encoded & 1) {
      if (magnitude > previous) return false;
      *out = previous - magnitude;
    } else {
      if (magnitude > SIZE_MAX - previous) return false;
      *out = previous + magnitude;
    }
    return true;
  }

  std::unique_ptr<Circuit<Field>> fail(CircuitReadErrorCode code,
                                       const ByteCursor& buf,
                                       size_t layer = SIZE_MAX,
                                       size_t term = SIZE_MAX) {
    last_error_ = {code, buf.offset().value, layer, term};
    return nullptr;
  }

  static bool read_index(ByteCursor& buf, size_t prev_ind, size_t* out) {
    size_t delta;
    if (!read_num(buf, &delta)) return false;
    size_t magnitude = delta >> 1;
    if (delta & 1) {
      if (magnitude > prev_ind) return false;
      *out = prev_ind - magnitude;
    } else {
      if (magnitude > SIZE_MAX - prev_ind) return false;
      *out = prev_ind + magnitude;
    }
    return true;
  }

  // This routine reads bytes written by serialize_* methods, and thus
  // only needs to handle values expressed in kBytesPerSizeT.
  // On 32-bit platforms, values which do not fit are recoverable parse errors.
  static bool read_num(ByteCursor& buf, size_t* out) {
    uint64_t r = 0;
    const uint8_t* p = nullptr;
    if (!buf.take(CircuitIO::kBytesPerSizeT, &p)) return false;
    for (size_t i = 0; i < CircuitIO::kBytesPerSizeT; ++i) {
      r |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    if (r > SIZE_MAX) return false;
    *out = static_cast<size_t>(r);
    return true;
  }

  const Field& f_;
  FieldID field_id_;
  CircuitReadError last_error_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_READER_H_
