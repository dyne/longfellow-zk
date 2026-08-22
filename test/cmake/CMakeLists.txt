add_executable(longfellow-zk-smoke-static smoke.cc)
target_link_libraries(longfellow-zk-smoke-static PRIVATE LongfellowZK::static)
add_test(NAME longfellow-zk-smoke-static COMMAND longfellow-zk-smoke-static)
set_tests_properties(longfellow-zk-smoke-static PROPERTIES LABELS base)

add_executable(longfellow-zk-smoke-shared smoke.cc)
target_link_libraries(longfellow-zk-smoke-shared PRIVATE LongfellowZK::shared)
add_test(NAME longfellow-zk-smoke-shared COMMAND longfellow-zk-smoke-shared)
set_tests_properties(longfellow-zk-smoke-shared PROPERTIES LABELS base)
