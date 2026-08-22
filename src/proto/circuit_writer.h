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

#ifndef PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_WRITER_H_
#define PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_WRITER_H_

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

#include "proto/circuit_io.h"
#include "sumcheck/circuit.h"
#include "sumcheck/quad.h"
#include "sumcheck/quad_builder.h"
#include "util/panic.h"

namespace proofs {

template <class Field>
class CircuitWriter {
  using Elt = typename Field::Elt;
  using QuadCorner = typename Quad<Field>::quad_corner_t;

 public:
  explicit CircuitWriter(const Field& f, FieldID field_id)
      : f_(f), field_id_(field_id) {}

  void to_bytes(const Circuit<Field>& sc_c, std::vector<uint8_t>& bytes,
                CircuitFormat format = CircuitFormat::kLfc1) {
    if (format == CircuitFormat::kLfc2) {
      to_lfc2_bytes(sc_c, bytes);
      return;
    }
    KvecBuilder<Field> kb(f_);
    // Collect constants
    for (const auto& layer : sc_c.l) {
      for (const auto& ec : *layer.quad) {
        kb.kstore(ec.v);
      }
    }

    // Write header
    bytes.push_back(CircuitIO::kLfc1Version);
    serialize_field_id(bytes, field_id_);
    serialize_size(bytes, sc_c.nv);
    serialize_size(bytes, sc_c.nc);
    serialize_size(bytes, sc_c.npub_in);
    serialize_size(bytes, sc_c.subfield_boundary);
    serialize_size(bytes, sc_c.ninputs);
    serialize_size(bytes, sc_c.l.size());

    // Write kvec
    auto kvec = kb.kvec();
    serialize_size(bytes, kvec->size());
    for (const auto& v : *kvec) {
      serialize_elt(bytes, v, f_);
    }

    // Serialize layers and quads
    for (const auto& layer : sc_c.l) {
      serialize_size(bytes, layer.logw);
      serialize_size(bytes, layer.nw);
      serialize_size(bytes, layer.quad->size());

      QuadCorner prevg(0), prevh0(0), prevh1(0);
      for (const auto& ec : *layer.quad) {
        serialize_index(bytes, ec.g, prevg);
        serialize_index(bytes, ec.h[0], prevh0);
        serialize_index(bytes, ec.h[1], prevh1);
        serialize_num(bytes, kb.kload(ec.v));
        prevg = ec.g;
        prevh0 = ec.h[0];
        prevh1 = ec.h[1];
      }
    }

    // Write circuit ID
    bytes.insert(bytes.end(), sc_c.id, sc_c.id + CircuitIO::kIdSize);
  }

 private:
  static void serialize_elt(std::vector<uint8_t>& bytes, const Elt& v,
                            const Field& f) {
    uint8_t buf[Field::kBytes];
    f.to_bytes_field(buf, v);
    bytes.insert(bytes.end(), buf, buf + Field::kBytes);
  }

  static void serialize_field_id(std::vector<uint8_t>& bytes, FieldID id) {
    serialize_num(bytes, static_cast<size_t>(id));
  }

  static void serialize_size(std::vector<uint8_t>& bytes, size_t sz) {
    serialize_num(bytes, sz);
  }

  // We write indices as differences from the previous index.  This
  // encoding appears to produce byte streams that compress better
  // under both gzip and xz compression.  For example, xz compresses
  // a 35MB test circuit to 2MB without delta encoding, and to 100KB
  // with delta encoding.  We have no real theory to explain this
  // phenomenon, but at least part of the reason is that the deltas
  // are usually smaller than the indices.
  static void serialize_index(std::vector<uint8_t>& bytes, QuadCorner index,
                              QuadCorner prev_index) {
    size_t ind = static_cast<size_t>(index);
    size_t prev_ind = static_cast<size_t>(prev_index);

    // Encode the delta IND - PREV_IND.  Since the delta can be
    // negative, and the rest of the code is unsigned only,
    // use the LSB as sign bit.
    if (ind >= prev_ind) {
      serialize_num(bytes, 2u * (ind - prev_ind));
    } else {
      serialize_num(bytes, 2u * (prev_ind - ind) + 1u);
    }
  }

  static void serialize_num(std::vector<uint8_t>& bytes, size_t g) {
    check(g <= CircuitIO::kMaxValue, "Violating small wire-label assumption");
    uint8_t tmp[CircuitIO::kBytesPerSizeT];
    for (size_t i = 0; i < CircuitIO::kBytesPerSizeT; ++i) {
      tmp[i] = static_cast<uint8_t>(g & 0xff);
      g >>= 8;
    }
    bytes.insert(bytes.end(), tmp, tmp + CircuitIO::kBytesPerSizeT);
  }

  static void serialize_varint(std::vector<uint8_t>& bytes, size_t value) {
    do {
      uint8_t byte = static_cast<uint8_t>(value & 0x7f);
      value >>= 7;
      if (value != 0) byte |= 0x80;
      bytes.push_back(byte);
    } while (value != 0);
  }

  static void serialize_delta(std::vector<uint8_t>& bytes, QuadCorner index,
                              QuadCorner previous) {
    const size_t value = static_cast<size_t>(index);
    const size_t prev = static_cast<size_t>(previous);
    serialize_varint(bytes, value >= prev ? 2 * (value - prev)
                                          : 2 * (prev - value) + 1);
  }

  void to_lfc2_bytes(const Circuit<Field>& sc_c, std::vector<uint8_t>& bytes) {
    bytes.insert(bytes.end(), CircuitIO::kLfc2Magic,
                 CircuitIO::kLfc2Magic + sizeof(CircuitIO::kLfc2Magic));
    KvecBuilder<Field> kb(f_);
    for (const auto& layer : sc_c.l)
      for (const auto& term : *layer.quad) kb.kstore(term.v);
    for (size_t value : {static_cast<size_t>(field_id_), sc_c.nv, sc_c.nc,
                         sc_c.npub_in, sc_c.subfield_boundary, sc_c.ninputs,
                         sc_c.l.size(), kb.kvec()->size()})
      serialize_varint(bytes, value);
    for (const auto& value : *kb.kvec()) serialize_elt(bytes, value, f_);
    for (const auto& layer : sc_c.l) {
      serialize_varint(bytes, layer.logw);
      serialize_varint(bytes, layer.nw);
      struct Delta { int32_t g, h0, h1; uint32_t constant; };
      std::vector<Delta> deltas;
      std::vector<uint32_t> tokens;
      QuadCorner previous_g(0), previous_h0(0), previous_h1(0);
      for (const auto& term : *layer.quad) {
        Delta delta{static_cast<int32_t>(static_cast<uint32_t>(term.g) - static_cast<uint32_t>(previous_g)),
                    static_cast<int32_t>(static_cast<uint32_t>(term.h[0]) - static_cast<uint32_t>(previous_h0)),
                    static_cast<int32_t>(static_cast<uint32_t>(term.h[1]) - static_cast<uint32_t>(previous_h1)),
                    static_cast<uint32_t>(kb.kload(term.v))};
        size_t index = 0;
        for (; index < deltas.size(); ++index) {
          const auto& old = deltas[index];
          if (old.g == delta.g && old.h0 == delta.h0 && old.h1 == delta.h1 && old.constant == delta.constant) break;
        }
        if (index == deltas.size()) deltas.push_back(delta);
        tokens.push_back(static_cast<uint32_t>(index));
        previous_g = term.g;
        previous_h0 = term.h[0];
        previous_h1 = term.h[1];
      }
      serialize_varint(bytes, deltas.size());
      for (const auto& delta : deltas) {
        auto zigzag = [](int32_t value) { return static_cast<uint32_t>((static_cast<uint32_t>(value) << 1) ^ static_cast<uint32_t>(value >> 31)); };
        serialize_varint(bytes, zigzag(delta.g)); serialize_varint(bytes, zigzag(delta.h0));
        serialize_varint(bytes, zigzag(delta.h1)); serialize_varint(bytes, delta.constant);
      }
      serialize_varint(bytes, 1);  // one canonical segment containing the term stream
      serialize_varint(bytes, tokens.size());
      for (uint32_t token : tokens) serialize_varint(bytes, token);
      serialize_varint(bytes, 1);  // execute segment 0 once
      serialize_varint(bytes, 0);
    }
    bytes.insert(bytes.end(), sc_c.id, sc_c.id + CircuitIO::kIdSize);
  }

  const Field& f_;
  FieldID field_id_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_WRITER_H_
