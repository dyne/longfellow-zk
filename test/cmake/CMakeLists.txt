add_executable(longfellow-zk-smoke-static smoke.cc)
target_link_libraries(longfellow-zk-smoke-static PRIVATE LongfellowZK::static)
add_test(NAME longfellow-zk-smoke-static COMMAND longfellow-zk-smoke-static)
set_tests_properties(longfellow-zk-smoke-static PROPERTIES LABELS base)

add_executable(longfellow-zk-smoke-shared smoke.cc)
target_link_libraries(longfellow-zk-smoke-shared PRIVATE LongfellowZK::shared)
add_test(NAME longfellow-zk-smoke-shared COMMAND longfellow-zk-smoke-shared)
set_tests_properties(longfellow-zk-smoke-shared PROPERTIES LABELS base)

add_executable(longfellow-zk-fixed-depth-merkle
  ../merkle/fixed_depth_sha256_merkle_membership_test.cc)
target_link_libraries(longfellow-zk-fixed-depth-merkle PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-fixed-depth-merkle PRIVATE -UNDEBUG)
endif()
add_test(NAME longfellow-zk-fixed-depth-merkle COMMAND longfellow-zk-fixed-depth-merkle)
set_tests_properties(longfellow-zk-fixed-depth-merkle PROPERTIES LABELS merkle)
