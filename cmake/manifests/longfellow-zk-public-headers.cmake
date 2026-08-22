# Paths remain relative to src/ so installation can preserve include spelling.
# The boundary inventory supplies the path-by-path approved public closure.
include("${CMAKE_CURRENT_LIST_DIR}/longfellow-zk-boundary.cmake")
set(LONGFELLOW_ZK_PUBLIC_HEADERS ${LONGFELLOW_ZK_BASE_HEADERS})
