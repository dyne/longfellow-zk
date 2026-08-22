// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_CPP20_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_CPP20_H_

#include <span>

#if __cplusplus < 202002L
#error "longfellow-zk requires C++20 or later"
#endif

#ifndef __cpp_lib_span
#error "longfellow-zk requires std::span"
#endif

namespace proofs {
template <class T>
using Span = std::span<T>;
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_CPP20_H_
