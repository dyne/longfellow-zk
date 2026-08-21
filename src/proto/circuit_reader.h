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
    last_error_ = {};
    if (!buf.have(8 * CircuitIO::kBytesPerSizeT + 1)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }

    const uint8_t* bytes = nullptr;
    if (!buf.read(1, &bytes)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
    }
    uint8_t version = bytes[0];
    if (version != 1) {
      return fail(CircuitReadErrorCode::kUnsupportedVersion, buf);
    }

    size_t fid_as_size_t, nv, nc, npub_in, subfield_boundary, ninputs, nl,
        numconst;
    if (!read_num(buf, &fid_as_size_t) || !read_num(buf, &nv) ||
        !read_num(buf, &nc) || !read_num(buf, &npub_in) ||
        !read_num(buf, &subfield_boundary) || !read_num(buf, &ninputs) ||
        !read_num(buf, &nl) || !read_num(buf, &numconst)) {
      return fail(CircuitReadErrorCode::kTruncated, buf);
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

    auto constants = std::make_shared<std::vector<Elt>>(numconst);
    for (size_t i = 0; i < numconst; ++i) {
      if (!buf.read(Field::kBytes, &bytes)) {
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
    if (!buf.read(CircuitIO::kIdSize, c->id)) {
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
  std::unique_ptr<Circuit<Field>> fail(CircuitReadErrorCode code,
                                       const ReadBuffer& buf,
                                       size_t layer = SIZE_MAX,
                                       size_t term = SIZE_MAX) {
    last_error_ = {code, buf.position(), layer, term};
    return nullptr;
  }

  static bool read_index(ReadBuffer& buf, size_t prev_ind, size_t* out) {
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
  static bool read_num(ReadBuffer& buf, size_t* out) {
    uint64_t r = 0;
    const uint8_t* p = nullptr;
    if (!buf.read(CircuitIO::kBytesPerSizeT, &p)) return false;
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
