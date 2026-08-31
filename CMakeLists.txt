cmake_minimum_required(VERSION 3.20)

set(LONGFELLOW_ZK_VERSION "1.0.0" CACHE STRING
    "Longfellow-ZK semantic version (without the v tag prefix)")
if(NOT LONGFELLOW_ZK_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR
    "LONGFELLOW_ZK_VERSION must be a strict numeric semantic version")
endif()
project(LongfellowZK VERSION ${LONGFELLOW_ZK_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(LONGFELLOW_ZK_BUILD_TESTING "Build Longfellow ZK qualification tests" ON)
option(LONGFELLOW_ZK_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(LONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY "Build the opt-in Google Rust parity C++ oracle" OFF)
option(LONGFELLOW_ZK_BUILD_PROFILING "Build the opt-in profiling workloads" OFF)

include(cmake/manifests/longfellow-zk-sources.cmake)
include(cmake/manifests/longfellow-zk-public-headers.cmake)

add_library(longfellow-zk-objects OBJECT ${LONGFELLOW_ZK_SOURCES})
add_library(longfellow-zk-static STATIC $<TARGET_OBJECTS:longfellow-zk-objects>)
set(LONGFELLOW_ZK_LIBRARY_TARGETS longfellow-zk-static)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
  add_library(longfellow-zk-shared SHARED $<TARGET_OBJECTS:longfellow-zk-objects>)
  list(APPEND LONGFELLOW_ZK_LIBRARY_TARGETS longfellow-zk-shared)
endif()

set_target_properties(longfellow-zk-objects PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
set_target_properties(longfellow-zk-static PROPERTIES
  OUTPUT_NAME longfellow-zk
  EXPORT_NAME static
)
if(TARGET longfellow-zk-shared)
  set_target_properties(longfellow-zk-shared PROPERTIES
    OUTPUT_NAME longfellow-zk
    EXPORT_NAME shared
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
  )
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-objects PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
endif()

if(LONGFELLOW_ZK_ENABLE_SANITIZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    message(FATAL_ERROR "LONGFELLOW_ZK_ENABLE_SANITIZERS requires GCC or Clang")
  endif()
  target_compile_options(longfellow-zk-objects PRIVATE
    -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1)
  target_link_options(longfellow-zk-static INTERFACE -fsanitize=address,undefined)
  if(TARGET longfellow-zk-shared)
    target_link_options(longfellow-zk-shared INTERFACE -fsanitize=address,undefined)
  endif()
endif()

if(LONGFELLOW_ZK_BUILD_PROFILING)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "LONGFELLOW_ZK_BUILD_PROFILING currently requires GNU C++ on Linux")
  endif()
  if(NOT CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo)$")
    message(WARNING "Profiling results are representative only with Release or RelWithDebInfo")
  endif()
  find_program(LONGFELLOW_ZK_GPROF_EXECUTABLE gprof REQUIRED)
  find_program(LONGFELLOW_ZK_PERF_EXECUTABLE perf)
endif()

foreach(target longfellow-zk-objects ${LONGFELLOW_ZK_LIBRARY_TARGETS})
  target_compile_features(${target} PUBLIC cxx_std_20)
  target_include_directories(${target}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk>
  )
endforeach()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-objects PRIVATE
    -Wall -Wextra -Wpedantic -fno-strict-overflow
  )
endif()

add_library(LongfellowZK::static ALIAS longfellow-zk-static)
if(TARGET longfellow-zk-shared)
  add_library(LongfellowZK::shared ALIAS longfellow-zk-shared)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
  add_executable(longfellow-zk-wasi-smoke cmake/wasi_smoke.cc)
  target_link_libraries(longfellow-zk-wasi-smoke PRIVATE LongfellowZK::static)
  target_link_options(longfellow-zk-wasi-smoke PRIVATE
    -mexec-model=reactor -Wl,--export=longfellow_zk_wasi_smoke)
  set_target_properties(longfellow-zk-wasi-smoke PROPERTIES SUFFIX ".wasm")
endif()

install(TARGETS ${LONGFELLOW_ZK_LIBRARY_TARGETS}
  EXPORT LongfellowZKTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

foreach(header IN LISTS LONGFELLOW_ZK_PUBLIC_HEADERS)
  file(RELATIVE_PATH header_relative "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/${header}")
  get_filename_component(header_directory "${header_relative}" DIRECTORY)
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/${header}"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk/${header_directory}")
endforeach()

install(EXPORT LongfellowZKTargets
  FILE LongfellowZKTargets.cmake
  NAMESPACE LongfellowZK::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZK
)

configure_package_config_file(
  cmake/LongfellowZKConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZK"
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZK"
)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/LongfellowZK)
install(FILES docs/abi.md docs/packaging.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZK)

set(CPACK_PACKAGE_NAME "longfellow-zk")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR "Dyne.org Foundation")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ")
include(CPack)

if(BUILD_TESTING AND LONGFELLOW_ZK_BUILD_TESTING)
  add_subdirectory(test/cmake)
endif()

if(LONGFELLOW_ZK_BUILD_PROFILING)
  add_library(longfellow-zk-gprof-objects OBJECT EXCLUDE_FROM_ALL
    ${LONGFELLOW_ZK_SOURCES})
  set_target_properties(longfellow-zk-gprof-objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
  target_compile_features(longfellow-zk-gprof-objects PUBLIC cxx_std_20)
  target_include_directories(longfellow-zk-gprof-objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_options(longfellow-zk-gprof-objects PRIVATE
    -Wall -Wextra -Wpedantic -fno-strict-overflow
    -fvisibility=hidden -fvisibility-inlines-hidden
    -pg -fno-omit-frame-pointer)
  add_library(longfellow-zk-gprof-static STATIC EXCLUDE_FROM_ALL
    $<TARGET_OBJECTS:longfellow-zk-gprof-objects>)
  target_compile_features(longfellow-zk-gprof-static PUBLIC cxx_std_20)
  target_include_directories(longfellow-zk-gprof-static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_options(longfellow-zk-gprof-static INTERFACE -pg)

  add_executable(longfellow-zk-profile-bip340 EXCLUDE_FROM_ALL
    projects/bip340/tests/bip340/bip340_test.cc)
  target_include_directories(longfellow-zk-profile-bip340 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/projects/bip340/include
    ${CMAKE_CURRENT_SOURCE_DIR}/projects/bip340/tests/bip340)
  target_link_libraries(longfellow-zk-profile-bip340 PRIVATE
    longfellow-zk-gprof-static)
  target_compile_options(longfellow-zk-profile-bip340 PRIVATE
    -pg -fno-omit-frame-pointer)

  set(LONGFELLOW_ZK_PROFILE_DIR "${CMAKE_CURRENT_BINARY_DIR}/profile")
  set(LONGFELLOW_ZK_PROFILE_REPORT "${LONGFELLOW_ZK_PROFILE_DIR}/gprof.txt")
  add_custom_target(longfellow-zk-profile
    COMMAND ${CMAKE_COMMAND}
      -DPROFILE_PROGRAM=$<TARGET_FILE:longfellow-zk-profile-bip340>
      -DGPROF_PROGRAM=${LONGFELLOW_ZK_GPROF_EXECUTABLE}
      -DPROFILE_DIR=${LONGFELLOW_ZK_PROFILE_DIR}
      -DPROFILE_REPORT=${LONGFELLOW_ZK_PROFILE_REPORT}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_gprof.cmake
    DEPENDS longfellow-zk-profile-bip340
    COMMENT "Profiling the BIP-340 end-to-end workload"
    VERBATIM)

  if(LONGFELLOW_ZK_PERF_EXECUTABLE)
    add_executable(longfellow-zk-profile-bip340-perf EXCLUDE_FROM_ALL
      projects/bip340/tests/bip340/bip340_test.cc)
    target_include_directories(longfellow-zk-profile-bip340-perf PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/projects/bip340/include
      ${CMAKE_CURRENT_SOURCE_DIR}/projects/bip340/tests/bip340)
    target_link_libraries(longfellow-zk-profile-bip340-perf PRIVATE
      LongfellowZK::static)
    target_compile_options(longfellow-zk-profile-bip340-perf PRIVATE
      -fno-omit-frame-pointer)

    set(LONGFELLOW_ZK_PERF_REPORT "${LONGFELLOW_ZK_PROFILE_DIR}/perf-report.txt")
    add_custom_target(longfellow-zk-profile-perf
      COMMAND ${CMAKE_COMMAND}
        -DPROFILE_PROGRAM=$<TARGET_FILE:longfellow-zk-profile-bip340-perf>
        -DPERF_PROGRAM=${LONGFELLOW_ZK_PERF_EXECUTABLE}
        -DPROFILE_DIR=${LONGFELLOW_ZK_PROFILE_DIR}
        -DPROFILE_REPORT=${LONGFELLOW_ZK_PERF_REPORT}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_perf.cmake
      DEPENDS longfellow-zk-profile-bip340-perf
      COMMENT "Sampling the BIP-340 end-to-end workload with perf"
      VERBATIM)
  endif()
endif()

# This target is deliberately opt-in and omitted from install/export rules.  The
# accompanying runner validates the pinned submodule before enabling it.
if(LONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY)
  add_executable(longfellow-zk-google-cpp-oracle EXCLUDE_FROM_ALL
    test/google_rust_parity/cpp_oracle.cc)
  target_link_libraries(longfellow-zk-google-cpp-oracle PRIVATE LongfellowZK::static)
  target_compile_features(longfellow-zk-google-cpp-oracle PRIVATE cxx_std_20)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(longfellow-zk-google-cpp-oracle PRIVATE -mpclmul -msse2)
  endif()
endif()
