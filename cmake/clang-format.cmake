find_program(PYTHON_EXECUTABLE python3 python)

if(NOT PYTHON_EXECUTABLE)
  message(WARNING "Python not found. Skipping lint and format checks.")
else()
  if(DEFINED ENV{LINT_AND_FORMAT_CHECK})
    set(LINT_AND_FORMAT_SCRIPT_PATH ${CMAKE_SOURCE_DIR}/tools/lint_and_format.py)
    message(STATUS "Checking code with clang-format...")
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${LINT_AND_FORMAT_SCRIPT_PATH} check
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      RESULT_VARIABLE clang_check_result
    )

    if(clang_check_result)
      message(FATAL_ERROR "Clang-format check failed with error code ${clang_check_result}")
    endif()

  else()
    set(LINT_AND_FORMAT_SCRIPT_PATH ${CMAKE_SOURCE_DIR}/tools/lint_and_format.py)
    message(STATUS "Formatting code with clang-format...")
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${LINT_AND_FORMAT_SCRIPT_PATH} format
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
  endif()
endif()
