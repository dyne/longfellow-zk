cmake_minimum_required(VERSION 3.20)

set(LONGFELLOW_ZK_VERSION "1.0.0" CACHE STRING
    "Longfellow-ZK semantic version (without the v tag prefix)")
if(NOT LONGFELLOW_ZK_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR
    "LONGFELLOW_ZK_VERSION must be a strict numeric semantic version")
endif()
project(LongfellowZKMDoc VERSION ${LONGFELLOW_ZK_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(LONGFELLOW_ZK_TARGET "LongfellowZK::static" CACHE STRING
    "Installed LongfellowZK target used by this project")
find_package(LongfellowZK CONFIG REQUIRED)
find_package(LongfellowZKECDSA CONFIG REQUIRED)
if(NOT TARGET ${LONGFELLOW_ZK_TARGET})
  message(FATAL_ERROR "LONGFELLOW_ZK_TARGET must name an installed LongfellowZK target")
endif()
find_path(ZSTD_INCLUDE_DIR zstd.h REQUIRED)
find_library(ZSTD_LIBRARY zstd REQUIRED)

add_library(mdoc STATIC
  src/mdoc_decompress.cc
  src/mdoc_generate_circuit.cc
  src/mdoc_zk.cc
  src/zk_spec.cc)
add_library(LongfellowZKMDoc::mdoc ALIAS mdoc)
target_compile_features(mdoc PUBLIC cxx_std_20)
target_include_directories(mdoc
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-mdoc>
  PRIVATE ${ZSTD_INCLUDE_DIR})
target_link_libraries(mdoc
  PUBLIC ${LONGFELLOW_ZK_TARGET} LongfellowZKECDSA::ecdsa
  PRIVATE ${ZSTD_LIBRARY})
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
  target_compile_options(mdoc PRIVATE -mpclmul)
endif()

add_executable(longfellow-zk-mdoc
  src/main.cc src/encoding.cc src/nanobench.cc)
target_include_directories(longfellow-zk-mdoc PRIVATE src)
target_link_libraries(longfellow-zk-mdoc PRIVATE LongfellowZKMDoc::mdoc)

install(TARGETS mdoc longfellow-zk-mdoc EXPORT LongfellowZKMDocTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-mdoc
  PATTERN "*.o" EXCLUDE
  PATTERN "*.tmp" EXCLUDE)
install(EXPORT LongfellowZKMDocTargets
  FILE LongfellowZKMDocTargets.cmake
  NAMESPACE LongfellowZKMDoc::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKMDoc)
configure_package_config_file(cmake/LongfellowZKMDocConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKMDocConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKMDoc)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKMDocConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKMDocConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKMDocConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKMDoc)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKMDoc)

if(BUILD_TESTING)
  add_test(NAME mdoc-proof-artifact
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/proof_artifact_test.sh
      $<TARGET_FILE:longfellow-zk-mdoc>
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/mdoc_00.json)
endif()
