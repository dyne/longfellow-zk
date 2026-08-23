cmake_minimum_required(VERSION 3.20)

project(LongfellowZKBIP340 VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(LONGFELLOW_ZK_TARGET "LongfellowZK::static" CACHE STRING
    "Installed LongfellowZK target used by this project")
find_package(LongfellowZK CONFIG REQUIRED)
if(NOT TARGET ${LONGFELLOW_ZK_TARGET})
  message(FATAL_ERROR "LONGFELLOW_ZK_TARGET must name an installed LongfellowZK target")
endif()

add_library(bip340 INTERFACE)
add_library(LongfellowZKBIP340::bip340 ALIAS bip340)
target_compile_features(bip340 INTERFACE cxx_std_20)
target_include_directories(bip340 INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-bip340>)
target_link_libraries(bip340 INTERFACE ${LONGFELLOW_ZK_TARGET})

install(TARGETS bip340 EXPORT LongfellowZKBIP340Targets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-bip340)
install(EXPORT LongfellowZKBIP340Targets
  FILE LongfellowZKBIP340Targets.cmake
  NAMESPACE LongfellowZKBIP340::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBIP340)
configure_package_config_file(cmake/LongfellowZKBIP340Config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBIP340Config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBIP340)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBIP340ConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBIP340Config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKBIP340ConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKBIP340)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKBIP340)

if(BUILD_TESTING)
  add_executable(bip340-test tests/bip340/bip340_test.cc)
  target_include_directories(bip340-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/bip340)
  target_link_libraries(bip340-test PRIVATE LongfellowZKBIP340::bip340)
  add_test(NAME bip340-test COMMAND bip340-test)
endif()
