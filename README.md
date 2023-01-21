# Ada

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from 
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

## Requirements

- A recent C++ compiler supporting C++17 (e.g., gcc 8 or better)
- [ICU](https://icu.unicode.org).

## Usage (CMake)

```
cmake -B build
cmake --build build
cd build
ctest .
```

