#!/bin/bash

cd $SRC/ada-url

mkdir build
AMALGAMATE_OUTPUT_PATH=./build/singleheader python3 singleheader/amalgamate.py

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/parse.cc -o parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE parse.o \
     -o $OUT/parse
