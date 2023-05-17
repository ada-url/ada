link_libraries(ada)
add_executable(wasm wasm.cpp)
set_target_properties(wasm PROPERTIES LINK_FLAGS    "-Os -s WASM=1 -s ENVIRONMENT=node -s EXPORT_NAME=loadWASM -s MODULARIZE=1 --bind --no-entry")