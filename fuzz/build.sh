#!/bin/bash

cd $SRC/ada-url

cmake -B build
cmake --build build -j$(nproc)

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/parse.cc -o parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE parse.o \
     -o $OUT/parse
