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

add_executable(longfellow-zk-native-merkle-tree ../merkle/native_merkle_tree_test.cc)
target_link_libraries(longfellow-zk-native-merkle-tree PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-native-merkle-tree PRIVATE -UNDEBUG)
endif()
add_test(NAME longfellow-zk-native-merkle-tree COMMAND longfellow-zk-native-merkle-tree)
set_tests_properties(longfellow-zk-native-merkle-tree PROPERTIES LABELS merkle)

add_executable(longfellow-zk-upstream-crypto-vectors
  ../vectors/upstream_crypto_vectors_test.cc)
target_link_libraries(longfellow-zk-upstream-crypto-vectors PRIVATE LongfellowZK::static)
add_test(NAME longfellow-zk-upstream-crypto-vectors
  COMMAND longfellow-zk-upstream-crypto-vectors)
set_tests_properties(longfellow-zk-upstream-crypto-vectors PROPERTIES
  LABELS vectors)

add_executable(longfellow-zk-flatsha256-regressions
  ../sha/flatsha256_circuit_regression_test.cc)
target_link_libraries(longfellow-zk-flatsha256-regressions PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-flatsha256-regressions PRIVATE -UNDEBUG)
endif()
add_test(NAME longfellow-zk-flatsha256-regressions
  COMMAND longfellow-zk-flatsha256-regressions)
set_tests_properties(longfellow-zk-flatsha256-regressions PROPERTIES LABELS sha)

add_executable(longfellow-zk-base64-decoder
  ../base64/base64_decoder_test.cc)
target_link_libraries(longfellow-zk-base64-decoder PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-base64-decoder PRIVATE -UNDEBUG)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
    target_compile_options(longfellow-zk-base64-decoder PRIVATE -mpclmul)
  endif()
endif()
add_test(NAME longfellow-zk-base64-decoder COMMAND longfellow-zk-base64-decoder)
set_tests_properties(longfellow-zk-base64-decoder PROPERTIES LABELS base64)

add_executable(longfellow-zk-cbor-host-decoder ../cbor/host_decoder_test.cc)
target_link_libraries(longfellow-zk-cbor-host-decoder PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-cbor-host-decoder PRIVATE -UNDEBUG)
endif()
add_test(NAME longfellow-zk-cbor-host-decoder COMMAND longfellow-zk-cbor-host-decoder)
set_tests_properties(longfellow-zk-cbor-host-decoder PROPERTIES LABELS cbor)

add_executable(longfellow-zk-cbor-byte-decoder ../cbor/cbor_byte_decoder_test.cc)
target_link_libraries(longfellow-zk-cbor-byte-decoder PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-cbor-byte-decoder PRIVATE -UNDEBUG)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
    target_compile_options(longfellow-zk-cbor-byte-decoder PRIVATE -mpclmul)
  endif()
endif()
add_test(NAME longfellow-zk-cbor-byte-decoder COMMAND longfellow-zk-cbor-byte-decoder)
set_tests_properties(longfellow-zk-cbor-byte-decoder PROPERTIES LABELS cbor)

add_executable(longfellow-zk-upstream-compiler-regressions
  ../compiler/upstream_compiler_regression_test.cc)
target_link_libraries(longfellow-zk-upstream-compiler-regressions PRIVATE LongfellowZK::static)
add_test(NAME longfellow-zk-upstream-compiler-regressions
  COMMAND longfellow-zk-upstream-compiler-regressions)
set_tests_properties(longfellow-zk-upstream-compiler-regressions PROPERTIES LABELS compiler)

add_executable(longfellow-zk-upstream-logic-regressions
  ../logic/upstream_logic_regression_test.cc)
target_link_libraries(longfellow-zk-upstream-logic-regressions PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
  target_compile_options(longfellow-zk-upstream-logic-regressions PRIVATE -mpclmul -msse2)
endif()
add_test(NAME longfellow-zk-upstream-logic-regressions
  COMMAND longfellow-zk-upstream-logic-regressions)
set_tests_properties(longfellow-zk-upstream-logic-regressions PROPERTIES LABELS logic)

add_executable(longfellow-zk-upstream-gf2-coding-regressions
  ../gf2/upstream_gf2_coding_regression_test.cc)
target_link_libraries(longfellow-zk-upstream-gf2-coding-regressions PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-upstream-gf2-coding-regressions PRIVATE -UNDEBUG)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
    target_compile_options(longfellow-zk-upstream-gf2-coding-regressions PRIVATE -mpclmul -msse2)
  endif()
endif()
add_test(NAME longfellow-zk-upstream-gf2-coding-regressions
  COMMAND longfellow-zk-upstream-gf2-coding-regressions)
set_tests_properties(longfellow-zk-upstream-gf2-coding-regressions PROPERTIES LABELS gf2)

add_executable(longfellow-zk-upstream-sumcheck-regressions
  ../sumcheck/upstream_sumcheck_regression_test.cc)
target_link_libraries(longfellow-zk-upstream-sumcheck-regressions PRIVATE LongfellowZK::static)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-upstream-sumcheck-regressions PRIVATE -UNDEBUG)
endif()
add_test(NAME longfellow-zk-upstream-sumcheck-regressions
  COMMAND longfellow-zk-upstream-sumcheck-regressions)
set_tests_properties(longfellow-zk-upstream-sumcheck-regressions PROPERTIES LABELS sumcheck)
