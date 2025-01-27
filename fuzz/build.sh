#!/bin/bash

cd $SRC/ada-url

mkdir build
AMALGAMATE_OUTPUT_PATH=./build/singleheader python3 singleheader/amalgamate.py

$CXX $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c fuzz/parse.cc -o parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE parse.o \
     -o $OUT/parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c fuzz/can_parse.cc -o can_parse.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE can_parse.o \
     -o $OUT/can_parse

$CXX $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c fuzz/idna.cc -o idna.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE idna.o \
     -o $OUT/idna

$CXX $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c fuzz/url_search_params.cc -o url_search_params.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE url_search_params.o \
     -o $OUT/url_search_params

# IMPORTANT
#
# We use std_regex_provider for testing purposes.
# It is not encouraged or recommended to be used within production
# environments due to security problems.
#
# Please do not enable it on production systems!
#
$CXX -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=1 \
     $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c fuzz/url_pattern.cc -o url_pattern.o

$CXX -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=1 \
     $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE \
     url_pattern.o \
     -o $OUT/url_pattern

$CXX $CFLAGS $CXXFLAGS \
     -std=c++20 \
     -I build/singleheader \
     -c build/singleheader/ada.cpp -o ada.o

$CC $CFLAGS $CXXFLAGS \
     -I build/singleheader \
     -c fuzz/ada_c.c -o ada_c.o

$CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE ./ada.o ada_c.o \
     -o $OUT/ada_c

cp $SRC/ada-url/fuzz/*.dict $SRC/ada-url/fuzz/*.options $OUT/
