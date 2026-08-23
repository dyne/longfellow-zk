cmake_minimum_required(VERSION 3.20)

project(LongfellowZKBlindZap VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(LONGFELLOW_ZK_TARGET "LongfellowZK::static" CACHE STRING
    "Installed LongfellowZK target used by this project")
find_package(LongfellowZK CONFIG REQUIRED)
find_package(LongfellowZKBIP340 CONFIG REQUIRED)
if(NOT TARGET ${LONGFELLOW_ZK_TARGET})
  message(FATAL_ERROR "LONGFELLOW_ZK_TARGET must name an installed LongfellowZK target")
endif()

add_library(blindzap INTERFACE)
add_library(LongfellowZKBlindZap::blindzap ALIAS blindzap)
target_compile_features(blindzap INTERFACE cxx_std_20)
target_include_directories(blindzap INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-blindzap>)
target_link_libraries(blindzap INTERFACE
  ${LONGFELLOW_ZK_TARGET} LongfellowZKBIP340::bip340)

add_executable(longfellow-zk-blindzap src/blindzap_main.cc)
target_link_libraries(longfellow-zk-blindzap PRIVATE LongfellowZKBlindZap::blindzap)

install(TARGETS blindzap longfellow-zk-blindzap EXPORT LongfellowZKBlindZapTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-blindzap)
install(EXPORT LongfellowZKBlindZapTargets
  FILE LongfellowZKBlindZapTargets.cmake NAMESPACE LongfellowZKBlindZap::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBlindZap)
configure_package_config_file(cmake/LongfellowZKBlindZapConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBlindZapConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBlindZap)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBlindZapConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBlindZapConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBlindZapConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBlindZap)
install(FILES README.md docs-circuit.md package-metadata.json
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKBlindZap)

if(BUILD_TESTING)
  function(add_blindzap_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE LongfellowZKBlindZap::blindzap)
    add_test(NAME ${target} COMMAND ${target} ${ARGN})
  endfunction()
  add_blindzap_test(blindzap-test tests/blindzap/blindzap_test.cc)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test/results")
  set_tests_properties(blindzap-test PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  add_blindzap_test(compressed-key-sha256-test tests/blindzap/compressed_key_sha256_test.cc)
  add_blindzap_test(key-ownership-test tests/blindzap/key_ownership_test.cc)
  add_blindzap_test(ripemd160-test tests/blindzap/ripemd160_test.cc)
  add_blindzap_test(blindzap-protocol-test tests/blindzap/protocol_test.cc)
  add_blindzap_test(blindzap-integration-test tests/blindzap/integration_test.cc)
  add_blindzap_test(blindzap-sage-test tests/blindzap/sage_vector_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/blindzap/testdata/blindzap_sage_vectors.json)
  add_test(NAME blindzap-cli-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/blindzap/cli_test.sh $<TARGET_FILE:longfellow-zk-blindzap>)
endif()
