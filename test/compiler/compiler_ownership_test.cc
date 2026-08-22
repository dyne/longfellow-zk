#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "ec/p256.h"
#include "proto/circuit_writer.h"

namespace {
using Field = proofs::Fp256Base;

void require(bool value, const char* message) {
  if (!value) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

std::unique_ptr<proofs::Circuit<Field>> build(proofs::QuadCircuit<Field>* q) {
  const size_t a = q->input_wire();
  const size_t b = q->input_wire();
  const size_t product = q->mul(a, b);
  const size_t reused = q->mul(a, b);  // CSE must retain this alias.
  const size_t shallow = q->add(product, reused);
  const size_t deep = q->mul(shallow, a);
  q->output_wire(shallow, 0);  // Forces a copy segment before the output.
  q->output_wire(deep, 1);
  q->assert0(q->sub(product, reused));
  return q->mkcircuit(1);
}
}  // namespace

int main() {
  std::vector<uint8_t> expected;
  for (size_t run = 0; run < 8; ++run) {
    proofs::QuadCircuit<Field> q(proofs::p256_base);
    auto circuit = build(&q);
    require(q.scheduler_temporary_storage_released_,
            "layered scheduler storage survived compilation");
    require(q.scheduler_renaming_scratch_released_,
            "renaming arena survived compilation");
    require(q.nwires_cse_eliminated_ == 1,
            "CSE behavior changed while testing ownership");
    require(q.nwires_overhead_ > 0,
            "copy-segment behavior changed while testing ownership");

    proofs::CircuitWriter<Field> writer(proofs::p256_base, proofs::P256_ID);
    std::vector<uint8_t> bytes;
    writer.to_bytes(*circuit, bytes);
    if (run == 0) {
      expected = bytes;
    } else {
      require(bytes == expected, "repeated compiler output is not exact");
    }
  }
  std::cout << "compiler ownership tests passed\n";
}
