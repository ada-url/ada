# Ada
![OpenSSF Scorecard Badge](https://api.securityscorecards.dev/projects/github.com/ada-url/ada/badge)
[![Ubuntu 22.04](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml)
[![VS17-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml)
[![VS17-clang-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml)
[![Ubuntu s390x (GCC 11)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml)

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from the
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

We also include a C wrapper for portability.

The Ada library passes the full range of tests from the specification,
across a wide range of platforms (e.g., Windows, Linux, macOS). It fully
supports the relevant [Unicode Technical Standard](https://www.unicode.org/reports/tr46/#ToUnicode).

## Requirements

- A recent C++ compiler supporting C++17. We test GCC 9 or better, LLVM 10 or better and Microsoft Visual Studio 2022.

The project is otherwise self-contained and it has no dependency.

## Usage

Ada supports two types of URL instances, `ada::url` and `ada::url_aggregator`. The usage is
the same in either case: we have an parsing function template `ada::parse` which can return
either a result of type `ada::result<ada::url>` or of type `ada::result<ada::url_aggregator>`
depending on your needs. The `ada::url_aggregator` class is smaller and it is backed by a precomputed
serialized URL string. The `ada::url` class is made of several separate strings for the various
components (path, host, and so forth).

### Parsing & Validation

- Parse and validate a URL

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
if (url) { /* URL is valid */ }
```

After calling 'parse', you *must* check that the result is valid before
accessing it when you are not sure that it will succeed. The following
code is unsafe:

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("some bad url");
url->get_href();
```

You should do...

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("some bad url");
if(url) {
  // next line is now safe:
  url->get_href();
} else {
  // report a parsing failure
}
```

For simplicity, in the examples below, we skip the check because
we know that parsing succeeds.

### Examples

- Get/Update credentials

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_username("username");
url->set_password("password");
// ada->get_href() will return "https://username:password@www.google.com/"
```

- Get/Update Protocol

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_protocol("wss");
// url->get_protocol() will return "wss:"
// url->get_href() will return "wss://www.google.com/"
```

- Get/Update host

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_host("github.com");
// url->get_host() will return "github.com"
// you can use `url.set_hostname` depending on your usage.
```

- Get/Update port

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_port("8080");
// url->get_port() will return "8080"
```

- Get/Update pathname

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_pathname("/my-super-long-path")
// url->get_pathname() will return "/my-super-long-path"
```

- Get/Update search/query

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_search("target=self");
// url->get_search() will return "?target=self"
```

- Get/Update hash/fragment

```cpp
ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>("https://www.google.com");
url->set_hash("is-this-the-real-life");
// url->get_hash() will return "#is-this-the-real-life"
```

### C wrapper

See the file `include/ada_c.h` for our C interface.

```C
#include "ada_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

static void ada_print(ada_string string) {
  printf("%.*s\n", (int)string.length, string.data);
}

int main(int c, char *arg[] ) {
  ada_url url = ada_parse("https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists");
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_print(ada_get_href(url)); // prints https://username:password@host:8080/pathname?query=true#hash-exists
  ada_print(ada_get_protocol(url)); // prints https:
  ada_print(ada_get_username(url)); // prints username
  ada_set_href(url, "https://www.yagiz.co");
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_set_hash(url, "new-hash");
  ada_set_hostname(url, "new-host");
  ada_set_host(url, "changed-host:9090");
  ada_set_pathname(url, "new-pathname");
  ada_set_search(url, "new-search");
  ada_set_protocol(url, "wss");
  ada_print(ada_get_href(url)); // will print wss://changed-host:9090/new-pathname?new-search#new-hash
  ada_free(url);
  return EXIT_SUCCESS;
}
```

When linking against the ada library from C++, be minding that ada requires access to the standard
C++ library. E.g., you may link with the C++ compiler.

### CMake dependency

See the file `tests/installation/CMakeLists.txt` for an example of how you might use ada from your own
CMake project, after having installed ada on your system.

## Installation

### Homebrew

Ada is available through [Homebrew](https://formulae.brew.sh/formula/ada-url#default).
You can install Ada using `brew install ada-url`.

## Contributing

### Building

Ada uses cmake as a build system. It's recommended you to run the following commands to build it locally.

- **Build**: `cmake -B build && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

Windows users need additional flags to specify the build configuration, e.g. `--config Release`.

The project can also be built via docker using default docker file of repository with following commands.

`docker build -t ada-builder . && docker run --rm -it -v ${PWD}:/repo ada-builder`

### Amalgamation

You may amalgamate all source files into only two files (`ada.h` and `ada.cpp`) by typing executing the Python
3 script `singleheader/amalgamate.py`. By default, the files are created in the `singleheader` directory.

### License

This code is made available under the Apache License 2.0 as well as the MIT license. For unicode processing, we rely on a few functions from UniLib which are licensed under the Mozilla Public License v.2.0.

Our tests include third-party code and data. The benchmarking code includes third-party code: it is provided for research purposes only and not part of the library.