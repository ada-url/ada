function(join_paths joined_path first_path_segment)
  set(temp_path "${first_path_segment}")
  foreach(current_segment IN LISTS ARGN)
    if(NOT ("${current_segment}" STREQUAL ""))
      if(IS_ABSOLUTE "${current_segment}")
        set(temp_path "${current_segment}")
      else()
        set(temp_path "${temp_path}/${current_segment}")
      endif()
    endif()
  endforeach()
  set(${joined_path} "${temp_path}" PARENT_SCOPE)
endfunction()
