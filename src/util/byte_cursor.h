// Copyright 2026 Dyne.org foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_BYTE_CURSOR_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_BYTE_CURSOR_H_

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "util/cpp20.h"

namespace proofs {

// Stable diagnostics for readers at an untrusted byte boundary.
enum class ParseErrorCode { kNone = 0, kInvalidInput, kTruncated, kResourceLimit };

struct ParseError {
  ParseErrorCode code = ParseErrorCode::kNone;
  size_t offset = 0;
  size_t requested = 0;
  size_t available = 0;
  explicit operator bool() const { return code != ParseErrorCode::kNone; }
};

struct ParseLimits {
  // Defaults are intentionally finite for every untrusted parser entry point.
  // They admit the largest supported LFC1 artifact while preventing a malformed
  // header from turning into an address-space sized allocation request.
  size_t bytes = 128 * 1024 * 1024;
  size_t allocations = 32 * 1024 * 1024;
  size_t elements = 32 * 1024 * 1024;
};

// A cursor-relative offset is deliberately not interchangeable with a byte
// count.  This stays internal to parser APIs and prevents accidental use as a
// buffer length without spelling out `.value`.
struct ByteOffset {
  size_t value;
};

// Span-like cursor. Failed operations never advance the cursor.
class ByteCursor {
 public:
  ByteCursor(const uint8_t* data, size_t size, ParseLimits limits = {})
      : data_(data), size_(size), limits_(limits) {
    if (data == nullptr && size != 0) {
      size_ = 0;
      error_ = {ParseErrorCode::kInvalidInput, 0, size, 0};
    }
  }
  ByteCursor(Span<const uint8_t> bytes, ParseLimits limits = {})
      : ByteCursor(bytes.data(), bytes.size(), limits) {}
  ByteCursor(std::nullptr_t, size_t, ParseLimits = {}) = delete;
  bool have(size_t count) const { return count <= remaining(); }
  size_t remaining() const { return size_ - offset_; }
  // Legacy source-compatible count accessor.
  size_t position() const { return offset_; }
  // Strong offset for parser code where a position must not be used as a
  // generic byte count without an explicit `.value` conversion.
  ByteOffset offset() const { return {offset_}; }
  const uint8_t* data() const { return data_ == nullptr ? nullptr : data_ + offset_; }
  const ParseError& error() const { return error_; }
  bool take(size_t count, const uint8_t** out) {
    if (out == nullptr) return fail(ParseErrorCode::kInvalidInput, count);
    if (count > limits_.bytes || !have(count)) {
      *out = nullptr;
      return fail(count > limits_.bytes ? ParseErrorCode::kResourceLimit : ParseErrorCode::kTruncated, count);
    }
    *out = count == 0 ? data_ : data_ + offset_;
    offset_ += count;
    limits_.bytes -= count;
    return true;
  }
  bool copy(size_t count, uint8_t* out) {
    if (out == nullptr && count != 0) return fail(ParseErrorCode::kInvalidInput, count);
    const uint8_t* source = nullptr;
    if (!take(count, &source)) return false;
    if (count != 0) std::memcpy(out, source, count);
    return true;
  }
  bool consume_allocation(size_t count) { return consume(count, &limits_.allocations); }
  bool consume_elements(size_t count) { return consume(count, &limits_.elements); }
 private:
  bool consume(size_t count, size_t* available) {
    if (count > *available) return fail(ParseErrorCode::kResourceLimit, count);
    *available -= count;
    return true;
  }
  bool fail(ParseErrorCode code, size_t requested) {
    if (!error_) error_ = {code, offset_, requested, remaining()};
    return false;
  }
  const uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t offset_ = 0;
  ParseLimits limits_;
  ParseError error_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_BYTE_CURSOR_H_
