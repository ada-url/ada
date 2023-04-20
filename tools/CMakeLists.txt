add_executable(adaparse adaparse.cpp)
target_link_libraries(adaparse PRIVATE ada)
target_include_directories(adaparse PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)
import_dependency(cxxopts jarro2783/cxxopts eb78730)
add_dependency(cxxopts)
target_link_libraries(adaparse PRIVATE cxxopts::cxxopts)
