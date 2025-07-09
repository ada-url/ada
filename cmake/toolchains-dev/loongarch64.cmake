# Usage:
# $ cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains-dev/loongarch64.cmake
set(CMAKE_SYSTEM_NAME Generic)

#set(target       loongarch64-unknown-linux-gnu)
set(target       loongarch64-linux-gnu)
set(version      14)
set(c_compiler   gcc)
set(cxx_compiler g++)

set(CMAKE_C_COMPILER   "${target}-${c_compiler}-${version}")
set(CMAKE_CXX_COMPILER "${target}-${cxx_compiler}-${version}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(LOONGARCH64_ISA "loongarch64")
set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-${LOONGARCH64_ISA}")

set(CMAKE_CXX_FLAGS "-mlsx")
