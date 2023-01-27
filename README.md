# Ada
[![Ubuntu 22.04](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml)
[![VS17-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml)
[![VS17-clang-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml)
[![Ubuntu s390x (GCC 11)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml)

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from the
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

## Requirements

- A recent C++ compiler supporting C++17. We test GCC 9 or better, LLVM 10 or better and Microsoft Visual Studio 2022.
- We use [ICU](https://icu.unicode.org) under non-Windows systems (macOS, Linux). Under Windows, [we rely on Microsoft's builtin IdnToAscii function](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-idntoascii).

## Local Development

Ada uses cmake as a build system. It's recommended you to run the following commands to build it locally.

- **Build**: `cmake -B build && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

Windows users need additional flags to specify the build configuration, e.g. `--config Release`.

**Installing ICU**: For macOS, you may install it with [brew](https://brew.sh) using `brew install icu4c`. Linux users may install ICU according to the their distribution: under Ubuntu, the command is `apt-get install -y libicu-dev`.


## Usage

- Parse and validate a URL

```cpp
ada::url url = ada::parse("https://www.google.com");
// url.is_valid will return true
```

- Get/Update credentials

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_username(url, "username");
url.set_password(url, "password");
// ada.get_href() will return "https://username:password@www.google.com"
```

- Get/Update Protocol

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_protocol("wss");
// url.get_protocol() will return "wss"
// url.get_href() will return "wss://www.google.com"
```

- Get/Update hostname

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_host("github.com");
// url.get_host() will return "github.com"
```

- Get/Update port

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_port("8080");
// url.get_port() will return "8080"
```

- Get/Update pathname

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_pathname("/my-super-long-path")
// url.get_pathname() will return "/my-super-long-path"
```

- Get/Update search/query

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_search("target=self");
// url.get_search() will return "?target=self"
```

- Get/Update hash/fragment

```cpp
ada::url url = ada::parse("https://www.google.com");
url.set_hash("is-this-the-real-life");
// url.get_hash() will return "#is-this-the-real-life"
```

## Amalgamation

You may amalgamate all source files into only two files (`ada.h` and `ada.cpp`) by typing executing the Python 3 script `singleheader/amalgamate.py`. By default, the files are created in the `singleheader` directory.

## Use ada as a CMake dependency

See the file `tests/installation/CMakeLists.txt` for an example of how you might use ada from your own CMake project, after having installed ada on your system.
