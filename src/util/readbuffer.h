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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "util/panic.h"

namespace proofs {

enum class ReadBufferError {
  kNone = 0,
  kInvalidInput,
  kUnderflow,
};

struct ReadBufferStatus {
  ReadBufferError error = ReadBufferError::kNone;
  size_t offset = 0;
  size_t requested = 0;
  size_t available = 0;

  explicit operator bool() const { return error == ReadBufferError::kNone; }
};

class ReadBuffer {
 public:
  explicit ReadBuffer(const uint8_t *buf, size_t sz)
      : buf_(buf), size_(sz), next_(0) {
    if (buf == nullptr && sz != 0) {
      status_ = {ReadBufferError::kInvalidInput, 0, sz, 0};
      size_ = 0;
    }
  }

  explicit ReadBuffer(const std::vector<uint8_t> &v)
      : ReadBuffer(v.data(), v.size()) {}

  // no copies
  ReadBuffer(const ReadBuffer &) = delete;
  ReadBuffer &operator=(const ReadBuffer &) = delete;

  // TRUE if at least N bytes remain
  bool have(size_t n) const { return remaining() >= n; }

  size_t remaining() const { return size_ - next_; }

  size_t position() const { return next_; }

  const ReadBufferStatus &status() const { return status_; }

  // Recoverable reads for untrusted input.  A failed read does not advance the
  // cursor and records the first failure with its offset and requested size.
  bool read(size_t n, const uint8_t **out) {
    if (out == nullptr) {
      record_error(ReadBufferError::kInvalidInput, n);
      return false;
    }
    if (!have(n)) {
      *out = nullptr;
      record_error(ReadBufferError::kUnderflow, n);
      return false;
    }
    *out = n == 0 ? buf_ : buf_ + next_;
    next_ += n;
    return true;
  }

  bool read(size_t n, uint8_t dest[/*n*/]) {
    if (dest == nullptr && n != 0) {
      record_error(ReadBufferError::kInvalidInput, n);
      return false;
    }
    const uint8_t *p = nullptr;
    if (!read(n, &p)) return false;
    if (n != 0) std::memcpy(dest, p, n);
    return true;
  }

  // Trusted-data compatibility accessors.  Parser code must use read() and
  // propagate false.  Calling next() on malformed data is an invariant error.
  const uint8_t *next(size_t n) {
    const uint8_t *p = nullptr;
    check(read(n, &p), "ReadBuffer::next underflow");
    return p;
  }

  void next(size_t n, uint8_t dest[/*n*/]) {
    check(read(n, dest), "ReadBuffer::next underflow");
  }

 private:
  void record_error(ReadBufferError error, size_t requested) {
    if (status_.error == ReadBufferError::kNone) {
      status_ = {error, next_, requested, remaining()};
    }
  }

  const uint8_t *buf_;
  size_t size_;
  size_t next_;
  ReadBufferStatus status_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_
