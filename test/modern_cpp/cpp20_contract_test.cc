// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>

#include "util/byte_cursor.h"

static_assert(__cplusplus >= 202002L, "the build must select C++20");
static_assert(std::is_constructible_v<proofs::ByteCursor,
                                      std::span<const uint8_t>>);
static_assert(!std::is_constructible_v<proofs::ByteCursor, std::nullptr_t,
                                       size_t>);
static_assert(!std::is_convertible_v<proofs::ByteOffset, size_t>);
static_assert(std::is_same_v<decltype(std::declval<proofs::ByteCursor>().position()), size_t>);

int main() {
  const std::array<uint8_t, 2> bytes = {1, 2};
  proofs::ByteCursor cursor{std::span<const uint8_t>(bytes)};
  return cursor.remaining() == bytes.size() ? 0 : 1;
}
