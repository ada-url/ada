# LoongArch64
You can now build and run the LoongArch64 code as needed:
GCC >= 14.1
Binutils >= 2.41
QEMU >= 9.2

Note that the compiler may be named `loongarch64-linux-gnu-g++`, without the `unknown` part.
Please adjust to your system.

```
$ sudo curl -L https://github.com/loongson/build-tools/releases/download/2025.06.06/qemu-loongarch64 --output /opt/qemu-loongarch64
$ sudo chmod +x /opt/qemu-loongarch64
$ export PATH=/opt:$PATH

$ export QEMU_LD_PREFIX="/usr/loongarch64-linux-gnu" # ubuntu 24.04
$ export QEMU_CPU="la464"
$ mkdir build && cd build
$ cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains-dev/loongarch64.cmake -DADA_TESTING=ON ../
$ make
```

Running tests with qemu
```
$ make test
or
$ ctest --output-on-failure --test-dir build
or
$ qemu-loongarch64 build/singleheader/cdemo
```

# RISC-V Vector Extension

The RISC-V Vector optimizations are supported by GCC-13, CLANG-16 and above.

Native builds will use the RVV code, if the specified `-march` ISA string or default target ISA supports the V extension.

For cross compilation, you may need to adjust the cross compiler target prefix in the toolchain file from `riscv64-linux-gnu` to e.g. `riscv64-unknown-linux-gnu` when using https://github.com/riscv-collab/riscv-gnu-toolchain.

```
# For Debian/Ubuntu
$ sudo apt install g++-riscv64-linux-gnu qemu-system-riscv qemu-user
$ mkdir build; cd build
$ export QEMU_LD_PREFIX="/usr/riscv64-linux-gnu"
$ export QEMU_CPU="rv64,v=on"
$ mkdir build && cd build
$ cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains-dev/riscv64-rvv.cmake -DADA_TESTING=ON ..
$ cmake --build -j $(nproc)
```
