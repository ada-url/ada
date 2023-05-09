add_executable(adaparse adaparse.cpp line_iterator.h)
target_link_libraries(adaparse PRIVATE ada)
target_include_directories(adaparse PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)
import_dependency(cxxopts jarro2783/cxxopts eb78730)
add_dependency(cxxopts)
import_dependency(fmt fmtlib/fmt a337011)
add_dependency(fmt)
target_link_libraries(adaparse PRIVATE cxxopts::cxxopts fmt::fmt)

if(MSVC OR MINGW)
  target_compile_definitions(adaparse PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

install(
   TARGETS
    adaparse
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)