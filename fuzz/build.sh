#!/bin/bash

cd $SRC/ada-url

mkdir build
AMALGAMATE_OUTPUT_PATH=./build/singleheader python3 singleheader/amalgamate.py

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/fuzz_parse.cc -o fuzz_parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse.o \
     -o $OUT/fuzz_parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/fuzz_can_parse.cc -o fuzz_can_parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_can_parse.o \
     -o $OUT/fuzz_can_parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/fuzz_idna.cc -o fuzz_idna.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_idna.o \
     -o $OUT/fuzz_idna

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/fuzz_url_search_params.cc -o fuzz_url_search_params.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_url_search_params.o \
     -o $OUT/fuzz_url_search_params

cp $SRC/ada-url/fuzz/*.dict $SRC/ada-url/fuzz/*.options $OUT/