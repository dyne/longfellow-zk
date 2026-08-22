cmake_minimum_required(VERSION 3.20)

project(LongfellowZK VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(LONGFELLOW_ZK_BUILD_TESTING "Build Longfellow ZK qualification tests" ON)

include(cmake/manifests/longfellow-zk-sources.cmake)
include(cmake/manifests/longfellow-zk-public-headers.cmake)

add_library(longfellow-zk-objects OBJECT ${LONGFELLOW_ZK_SOURCES})
add_library(longfellow-zk-static STATIC $<TARGET_OBJECTS:longfellow-zk-objects>)
add_library(longfellow-zk-shared SHARED $<TARGET_OBJECTS:longfellow-zk-objects>)

set_target_properties(longfellow-zk-objects PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
set_target_properties(longfellow-zk-static PROPERTIES
  OUTPUT_NAME longfellow-zk
  EXPORT_NAME static
)
set_target_properties(longfellow-zk-shared PROPERTIES
  OUTPUT_NAME longfellow-zk
  EXPORT_NAME shared
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(longfellow-zk-objects PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
endif()

foreach(target longfellow-zk-objects longfellow-zk-static longfellow-zk-shared)
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
add_library(LongfellowZK::shared ALIAS longfellow-zk-shared)

install(TARGETS longfellow-zk-static longfellow-zk-shared
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
install(FILES docs/abi.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZK)

if(BUILD_TESTING AND LONGFELLOW_ZK_BUILD_TESTING)
  add_subdirectory(test/cmake)
endif()
