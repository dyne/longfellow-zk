// Portable adaptation of google-longfellow-zk/lib/circuits/cbor_parser/cbor_byte_decoder_test.cc.
#include <cassert>
#include <cstddef>

#include "algebra/fp.h"
#include "circuits/cbor_parser/cbor_byte_decoder.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"

namespace proofs {
namespace {

template <class Field>
void CheckDecodeOneV8(const Field& field) {
  using Backend = EvaluationBackend<Field>;
  using CircuitLogic = Logic<Field, Backend>;
  using CounterL = Counter<CircuitLogic>;
  const Backend backend(field, false);
  const CircuitLogic logic(&backend, field);
  const CounterL counter(logic);
  const CborByteDecoder<CircuitLogic> decoder(logic);
  for (size_t type = 0; type < 8; ++type) for (size_t count = 0; count < 32; ++count) {
    const size_t byte = (type << 5) | count;
    const auto decoded = decoder.decode_one_v8(logic.template vbit<8>(byte));
    const bool atom = type < 2, string = type == 2 || type == 3;
    const bool array = type == 4, map = type == 5, items = array || map;
    const bool tag = type == 6, special = type == 7;
    const bool simple = special && count >= 20 && count < 24;
    const bool count_0_23 = count < 24, count_24_27 = count >= 24 && count < 28;
    const bool count24 = count == 24, count25 = count == 25;
    const bool count26 = count == 26, count27 = count == 27;
    bool next_length = false, next_count = false, invalid = false;
    size_t length = 0;
    if (atom || tag) {
      if (count_0_23) length = 1;
      else if (count24) length = 2;
      else if (count25) length = 3;
      else if (count26) length = 5;
      else if (count27) length = 9;
      else invalid = true;
    } else if (items) {
      if (count_0_23) length = 1;
      else if (count24) { length = 2; next_count = true; }
      else invalid = true;
    } else if (string) {
      if (count_0_23) length = 1 + count;
      else if (count24) { length = 2; next_length = true; }
      else invalid = true;
    } else if (simple) length = 1;
    else invalid = true;
    auto equal_bit = [&](const auto& actual, bool expected) {
      assert(logic.eval(actual) == logic.eval(logic.bit(expected)));
    };
    equal_bit(decoded.atomp, atom); equal_bit(decoded.itemsp, items);
    equal_bit(decoded.stringp, string); equal_bit(decoded.arrayp, array);
    equal_bit(decoded.mapp, map); equal_bit(decoded.tagp, tag);
    equal_bit(decoded.specialp, special); equal_bit(decoded.simple_specialp, simple);
    equal_bit(decoded.count0_23, count_0_23); equal_bit(decoded.count24_27, count_24_27);
    equal_bit(decoded.count24, count24); equal_bit(decoded.count25, count25);
    equal_bit(decoded.count26, count26); equal_bit(decoded.count27, count27);
    equal_bit(decoded.length_plus_next_v8, next_length);
    equal_bit(decoded.count_is_next_v8, next_count); equal_bit(decoded.invalid, invalid);
    if (!invalid) assert(decoded.length.e == counter.as_counter(length).e);
    assert(decoded.count_as_counter.e == counter.as_counter(count).e);
    assert(decoded.as_counter.e == counter.as_counter(byte).e);
    assert(decoded.as_scalar == logic.konst(byte));
    for (size_t bit = 0; bit < 8; ++bit)
      equal_bit(decoded.as_bits[bit], (byte >> bit) & 1u);
  }
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::CheckDecodeOneV8(proofs::Fp<1>("18446744073709551557"));
  proofs::CheckDecodeOneV8(proofs::GF2_128<>());
  return 0;
}
