if(NOT DEFINED PROFILE_PROGRAM OR NOT DEFINED PERF_PROGRAM OR
   NOT DEFINED PROFILE_DIR OR NOT DEFINED PROFILE_REPORT)
  message(FATAL_ERROR "run_perf.cmake requires PROFILE_PROGRAM, PERF_PROGRAM, PROFILE_DIR, and PROFILE_REPORT")
endif()

file(MAKE_DIRECTORY "${PROFILE_DIR}")
set(perf_data "${PROFILE_DIR}/perf.data")
file(REMOVE "${perf_data}")

execute_process(
  COMMAND "${PERF_PROGRAM}" record -F 999 --call-graph dwarf
          --output "${perf_data}" -- "${PROFILE_PROGRAM}" --profile 10
  WORKING_DIRECTORY "${PROFILE_DIR}"
  RESULT_VARIABLE profile_result)
if(NOT profile_result EQUAL 0)
  message(FATAL_ERROR
    "perf record failed with exit code ${profile_result}; check /proc/sys/kernel/perf_event_paranoid and perf permissions")
endif()

execute_process(
  COMMAND "${PERF_PROGRAM}" report --stdio --no-children
          --input "${perf_data}"
  OUTPUT_FILE "${PROFILE_REPORT}"
  RESULT_VARIABLE report_result)
if(NOT report_result EQUAL 0)
  message(FATAL_ERROR "perf report failed with exit code ${report_result}")
endif()

message(STATUS "Wrote perf report to ${PROFILE_REPORT}")
