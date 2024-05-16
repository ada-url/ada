#!/bin/bash

cd $SRC/ada-url

rm -r build
mkdir build
AMALGAMATE_OUTPUT_PATH=./build/singleheader python3 singleheader/amalgamate.py

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/parse.cc -o parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE parse.o \
     -o $OUT/parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/can_parse.cc -o can_parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE can_parse.o \
     -o $OUT/can_parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/idna.cc -o idna.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE idna.o \
     -o $OUT/idna

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/url_search_params.cc -o url_search_params.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE url_search_params.o \
     -o $OUT/url_search_params

$CXX $CFLAGS $CXXFLAGS \
     -std=c++17 \
     -I build/singleheader \
     -c fuzz/href.cc -o href.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE href.o \
     -o $OUT/href

cp $SRC/ada-url/fuzz/*.dict $SRC/ada-url/fuzz/*.options $OUT/
