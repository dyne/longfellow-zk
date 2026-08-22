# The only compiled inputs for the future liblongfellow-zk targets.  The
# boundary inventory owns the path-by-path list; this target-facing manifest
# deliberately selects only its base subset.
include("${CMAKE_CURRENT_LIST_DIR}/longfellow-zk-boundary.cmake")
set(LONGFELLOW_ZK_SOURCES ${LONGFELLOW_ZK_BASE_SOURCES})
