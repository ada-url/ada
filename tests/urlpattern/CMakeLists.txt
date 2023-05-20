
file(GLOB_RECURSE urlpattern_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.json)
foreach(urlpattern_file ${urlpattern_files})
  configure_file(${urlpattern_file} ${urlpattern_file} COPYONLY)
endforeach(urlpattern_file)
