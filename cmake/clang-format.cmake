find_program(PYTHON_EXECUTABLE python3 python)

if(NOT PYTHON_EXECUTABLE)
  message(WARNING "Python not found. Skipping lint and format checks.")
else()
  set(LINT_AND_FORMAT_SCRIPT_PATH ${CMAKE_SOURCE_DIR}/tools/lint_and_format.py)

  # Should run on CI
  if(DEFINED ENV{LINT_AND_FORMAT_CHECK})
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
    if(DEFINED ENV{FORMAT_ENABLED})
      message(STATUS "Formatting code with clang-format...")
      execute_process(
        COMMAND ${PYTHON_EXECUTABLE} ${LINT_AND_FORMAT_SCRIPT_PATH} format
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE clang_format_result
      )

      if(clang_format_result)
        message(FATAL_ERROR "Clang-format format failed with error code ${clang_check_result}")
      endif()
    else()
      message(STATUS "Code formatting is not enabled.")
    endif()
  endif()
endif()
