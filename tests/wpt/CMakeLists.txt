
file(GLOB_RECURSE wpt_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.json)
foreach(wpt_file ${wpt_files})
  configure_file(${wpt_file} ${wpt_file} COPYONLY)
endforeach(wpt_file)
