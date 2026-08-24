cmake_minimum_required(VERSION 3.20)

project(LongfellowZKECDSA VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(LONGFELLOW_ZK_TARGET "LongfellowZK::static" CACHE STRING
    "Installed LongfellowZK target used by this project")
find_package(LongfellowZK CONFIG REQUIRED)
if(NOT TARGET ${LONGFELLOW_ZK_TARGET})
  message(FATAL_ERROR "LONGFELLOW_ZK_TARGET must name an installed LongfellowZK target")
endif()

add_library(ecdsa INTERFACE)
add_library(LongfellowZKECDSA::ecdsa ALIAS ecdsa)
target_compile_features(ecdsa INTERFACE cxx_std_20)
target_include_directories(ecdsa INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-ecdsa>)
target_link_libraries(ecdsa INTERFACE ${LONGFELLOW_ZK_TARGET})

install(TARGETS ecdsa EXPORT LongfellowZKECDSATargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-ecdsa)
install(EXPORT LongfellowZKECDSATargets
  FILE LongfellowZKECDSATargets.cmake
  NAMESPACE LongfellowZKECDSA::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKECDSA)
configure_package_config_file(cmake/LongfellowZKECDSAConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKECDSAConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKECDSA)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKECDSAConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKECDSAConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKECDSAConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKECDSA)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKECDSA)

if(BUILD_TESTING)
  if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
    add_executable(ecdsa-wasi-verify-smoke tests/wasi_verify_smoke.cc)
    target_link_libraries(ecdsa-wasi-verify-smoke PRIVATE LongfellowZKECDSA::ecdsa)
    target_link_options(ecdsa-wasi-verify-smoke PRIVATE
      -mexec-model=reactor
      -Wl,-z,stack-size=1048576
      -Wl,--export=longfellow_zk_ecdsa_wasi_verify)
    set_target_properties(ecdsa-wasi-verify-smoke PROPERTIES SUFFIX ".wasm")
  else()
    add_executable(ecdsa-module-test tests/verify_module_test.cc)
    target_link_libraries(ecdsa-module-test PRIVATE LongfellowZKECDSA::ecdsa)
    add_test(NAME ecdsa-module-test COMMAND ecdsa-module-test)
  endif()
endif()
