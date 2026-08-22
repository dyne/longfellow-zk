// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <type_traits>

#include "arrays/dense.h"
#include "ec/p256.h"

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

void test_move_and_clone_contract() {
  static_assert(!std::is_copy_constructible<Dense<Field>>::value,
                "Dense must not silently copy a witness");
  static_assert(!std::is_copy_assignable<Dense<Field>>::value,
                "Dense must not silently copy-assign a witness");
  static_assert(std::is_nothrow_move_constructible<Dense<Field>>::value,
                "Dense transfer must be noexcept");
  static_assert(std::is_nothrow_move_assignable<Dense<Field>>::value,
                "Dense transfer assignment must be noexcept");

  Dense<Field> dense(2, 2);
  static_assert(std::is_same_v<decltype(dense.values()), std::span<Field::Elt>>);
  dense.v_[0] = p256_base.one();
  auto copy = dense.clone();
  copy->v_[0] = p256_base.zero();
  require(dense.v_[0] == p256_base.one(), "clone was not a deep copy");

  Dense<Field> moved(std::move(dense));
  require(moved.n0_ == 2 && moved.n1_ == 2 && moved.v_.size() == 4,
          "move construction lost dimensions or values");
  Dense<Field> assigned(1, 1);
  assigned = std::move(moved);
  require(assigned.n0_ == 2 && assigned.n1_ == 2 && assigned.v_.size() == 4,
          "move assignment lost dimensions or values");
}

void test_row_factory_contract() {
  const std::array<Field::Elt, 2> values = {p256_base.one(), p256_base.zero()};
  auto dense = Dense<Field>::from_row(values);
  require(dense.n0_ == 1 && dense.n1_ == values.size(), "row factory dimensions");
  require(dense.values()[0] == p256_base.one(), "row factory values");
  require_abort([] { (void)Dense<Field>::from_row(std::span<const Field::Elt>{}); }, "empty row factory accepted");
}

void test_lifetime_counters() {
  require(Dense<Field>::testing_live_elements() == 0,
          "previous Dense allocation remained live");
  {
    Dense<Field> dense(2, 3);
    require(Dense<Field>::testing_live_elements() == 6,
            "Dense allocation counter missed construction");
    auto copy = dense.clone();
    require(Dense<Field>::testing_live_elements() == 12,
            "Dense allocation counter missed clone");
    copy.reset();
    require(Dense<Field>::testing_live_bytes() == 6 * sizeof(Field::Elt),
            "Dense allocation counter missed reset");
  }
  require(Dense<Field>::testing_live_elements() == 0,
          "Dense allocation counter missed destruction");
}

void test_dimensions_are_checked() {
  require(Dense<Field>::checked_element_count(2, 3) == 6,
          "valid Dense dimensions were rejected");
  require_abort(
      [] { (void)Dense<Field>(std::numeric_limits<size_t>::max(), 2); },
      "overflowing Dense dimensions did not abort");
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::test_move_and_clone_contract();
  proofs::test_lifetime_counters();
  proofs::test_dimensions_are_checked();
  proofs::test_row_factory_contract();
  return 0;
}
