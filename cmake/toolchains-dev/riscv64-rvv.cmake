# Usage:
# $ cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains-dev/riscv64-rvv.cmake
set(CMAKE_SYSTEM_NAME Generic)

set(target       riscv64-linux-gnu)
set(c_compiler   gcc)
set(cxx_compiler g++)

set(CMAKE_C_COMPILER   "${target}-${c_compiler}")
set(CMAKE_CXX_COMPILER "${target}-${cxx_compiler}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-riscv64")

set(CMAKE_CXX_FLAGS "-march=rv64gcv")
