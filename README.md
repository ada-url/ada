# Ada

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from 
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

## Requirements

- [ICU](https://icu.unicode.org)

## Usage (CMake)

```
cmake -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/icu4c -B build
cmake --build build
cd build
ctest .
```
