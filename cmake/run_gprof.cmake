if(NOT DEFINED PROFILE_PROGRAM OR NOT DEFINED GPROF_PROGRAM OR
   NOT DEFINED PROFILE_DIR OR NOT DEFINED PROFILE_REPORT)
  message(FATAL_ERROR "run_gprof.cmake requires PROFILE_PROGRAM, GPROF_PROGRAM, PROFILE_DIR, and PROFILE_REPORT")
endif()

file(MAKE_DIRECTORY "${PROFILE_DIR}")
file(REMOVE "${PROFILE_DIR}/gmon.out")

execute_process(
  COMMAND "${PROFILE_PROGRAM}" --profile 5
  WORKING_DIRECTORY "${PROFILE_DIR}"
  RESULT_VARIABLE profile_result)
if(NOT profile_result EQUAL 0)
  message(FATAL_ERROR "Profiling workload failed with exit code ${profile_result}")
endif()
if(NOT EXISTS "${PROFILE_DIR}/gmon.out")
  message(FATAL_ERROR "Profiling workload did not produce ${PROFILE_DIR}/gmon.out")
endif()

execute_process(
  COMMAND "${GPROF_PROGRAM}" -b "${PROFILE_PROGRAM}" "${PROFILE_DIR}/gmon.out"
  OUTPUT_FILE "${PROFILE_REPORT}"
  RESULT_VARIABLE gprof_result)
if(NOT gprof_result EQUAL 0)
  message(FATAL_ERROR "gprof failed with exit code ${gprof_result}")
endif()

message(STATUS "Wrote profiling report to ${PROFILE_REPORT}")
