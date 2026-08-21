// Copyright 2026 Dyne.org foundation
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

#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

#include "cbor/host_decoder.h"
#include "ec/p256.h"
#include "proto/circuit_reader.h"
#include "sumcheck/circuit.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"

namespace proofs {
namespace {

using Field = Fp256Base;

void require(bool condition, const char* why) {
  if (!condition) {
    std::cerr << "not ok - " << why << '\n';
    std::exit(1);
  }
}

template <class Fn>
void require_abort(Fn fn, const char* why) {
  const pid_t pid = fork();
  require(pid >= 0, "fork failed");
  if (pid == 0) {
    fn();
    _exit(0);
  }

  int status = 0;
  require(waitpid(pid, &status, 0) == pid, "waitpid failed");
  require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, why);
}

void test_internal_invariants_abort() {
  check(true, "true invariant");
  require_abort([] { check(false, "intentional invariant failure"); },
                "check(false) did not abort");

  const uint8_t one_byte[] = {0x42};
  require_abort(
      [&] {
        ReadBuffer trusted(one_byte, sizeof(one_byte));
        (void)trusted.next(2);
      },
      "trusted ReadBuffer::next underflow did not abort");
}

void test_recoverable_buffer_underflow() {
  const uint8_t one_byte[] = {0x42};
  ReadBuffer buf(one_byte, sizeof(one_byte));
  const uint8_t* out = nullptr;
  require(!buf.read(2, &out), "oversized recoverable read succeeded");
  require(out == nullptr, "failed recoverable read returned a pointer");
  require(buf.position() == 0, "failed recoverable read advanced cursor");
  require(buf.remaining() == 1, "failed recoverable read changed remaining");
  require(buf.status().error == ReadBufferError::kUnderflow,
          "recoverable read did not report underflow");
  require(buf.status().offset == 0 && buf.status().requested == 2 &&
              buf.status().available == 1,
          "recoverable read status lacks boundary details");

  ReadBuffer invalid(nullptr, 1);
  require(invalid.status().error == ReadBufferError::kInvalidInput,
          "null non-empty buffer was accepted");
}

void test_malformed_circuit_is_recoverable() {
  const Field& field = p256_base;
  const std::vector<uint8_t> truncated = {1};
  ReadBuffer buf(truncated);
  CircuitReader<Field> reader(field, P256_ID);
  require(reader.from_bytes(buf, true) == nullptr,
          "truncated circuit was accepted");
  require(reader.last_error().code == CircuitReadErrorCode::kTruncated,
          "truncated circuit lacks structured error");
}

void test_malformed_proof_is_recoverable() {
  const Field& field = p256_base;
  Circuit<Field> circuit{};
  circuit.nv = 1;
  circuit.logv = 0;
  circuit.nc = 1;
  circuit.logc = 0;
  circuit.nl = 1;
  circuit.ninputs = 2;
  circuit.npub_in = 1;
  circuit.subfield_boundary = 1;
  auto constants =
      std::make_shared<std::vector<typename Field::Elt>>(1, field.one());
  auto deltas = std::make_shared<typename Quad<Field>::delta_table_t>();
  deltas->push_back(typename Quad<Field>::delta_corner{
      0, {0, 0}, 0});
  auto quad = std::make_unique<Quad<Field>>(1, constants, deltas);
  quad->assign(0, 0);
  circuit.l.push_back(Layer<Field>{
      .nw = 2,
      .logw = 1,
      .quad = std::unique_ptr<const Quad<Field>>(std::move(quad))});

  ZkProof<Field> proof(circuit, 4, 2);
  const std::vector<uint8_t> empty;
  ReadBuffer buf(empty);
  require(!proof.read(buf, field), "empty proof was accepted");
  require(proof.last_read_error().code == ProofReadErrorCode::kTruncated &&
              proof.last_read_error().section == ProofReadSection::kCommitment,
          "truncated proof lacks structured error");

  ZkProof<Field> invalid_geometry(circuit, 4, 2, 0);
  ReadBuffer invalid_geometry_buf(empty);
  require(!invalid_geometry.read(invalid_geometry_buf, field),
          "invalid proof geometry was accepted");
  require(invalid_geometry.last_read_error().code ==
              ProofReadErrorCode::kUnsupportedGeometry,
          "invalid proof geometry lacks a structured error");
}

void test_untrusted_cbor_lookup_is_recoverable() {
  const uint8_t scalar[] = {0x01};
  size_t pos = 0;
  CborDoc scalar_doc;
  require(scalar_doc.decode(scalar, sizeof(scalar), pos, 0),
          "valid scalar CBOR failed to decode");
  require(scalar_doc.aref(0) == nullptr,
          "array lookup on scalar did not fail recoverably");

  const uint8_t array[] = {0x81, 0x01};
  pos = 0;
  CborDoc array_doc;
  require(array_doc.decode(array, sizeof(array), pos, 0),
          "valid array CBOR failed to decode");
  require(array_doc.aref(1) == nullptr,
          "out-of-bounds array lookup did not fail recoverably");

  std::vector<uint8_t> nested_tags(66, 0xc0);
  nested_tags.push_back(0x01);
  pos = 0;
  CborDoc nested_doc;
  require(!nested_doc.decode(nested_tags.data(), nested_tags.size(), pos, 0),
          "excessively nested CBOR was accepted");
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::test_internal_invariants_abort();
  proofs::test_recoverable_buffer_underflow();
  proofs::test_malformed_circuit_is_recoverable();
  proofs::test_malformed_proof_is_recoverable();
  proofs::test_untrusted_cbor_lookup_is_recoverable();
  std::cout << "ok - fatal invariants and recoverable parsers\n";
  return 0;
}
