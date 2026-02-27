# Ada
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ada-url/ada/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ada-url/ada)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/7085/badge)](https://bestpractices.coreinfrastructure.org/projects/7085)
[![Ubuntu 22.04](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml)
[![VS17-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml)
[![VS17-clang-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml)
[![Ubuntu s390x (GCC 11)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml)

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from the
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

Ada library also includes a [URLPattern](https://url.spec.whatwg.org/#urlpattern) implementation
that is compatible with the [web-platform tests](https://github.com/web-platform-tests/wpt/tree/master/urlpattern).

The Ada library passes the full range of tests from the specification,
across a wide range of platforms (e.g., Windows, Linux, macOS). It fully
supports the relevant [Unicode Technical Standard](https://www.unicode.org/reports/tr46/#ToUnicode).

A common use of a URL parser is to take a URL string and normalize it.
The WHATWG URL specification has been adopted by most browsers.  Other tools, such as curl and many
standard libraries, follow the RFC 3986. The following table illustrates possible differences in practice
(encoding of the host, encoding of the path):

| string source           | string value                                                |
|:------------------------|:------------------------------------------------------------|
| input string            | https://www.7‑Eleven.com/Home/Privacy/Montréal              |
| ada's normalized string | https://www.xn--7eleven-506c.com/Home/Privacy/Montr%C3%A9al |
| curl 7.87               | (returns the original unchanged)                            |

## Ada is fast.

On a benchmark where we need to validate and normalize [thousands URLs found
on popular websites](https://github.com/ada-url/url-various-datasets/tree/main/top100),
we find that ada can be several times faster than popular competitors (system: Apple MacBook 2022
with LLVM 14).


```
      ada ▏  188 ns/URL ███▏
servo url ▏  664 ns/URL ███████████▎
     CURL ▏ 1471 ns/URL █████████████████████████
```

Ada has improved the performance of the popular JavaScript environment Node.js:

> Since Node.js 18, a new URL parser dependency was added to Node.js — Ada. This addition bumped the Node.js performance when parsing URLs to a new level. Some results could reach up to an improvement of **400%**. ([State of Node.js Performance 2023](https://blog.rafaelgss.dev/state-of-nodejs-performance-2023))

The Ada library is used by important systems besides Node.js such as Redpanda, Kong, Telegram, DataDog, and Cloudflare Workers.

[![the ada library](http://img.youtube.com/vi/tQ-6OWRDsZg/0.jpg)](https://www.youtube.com/watch?v=tQ-6OWRDsZg)<br />

### Requirements

The project is otherwise self-contained and it has no dependency.
A recent C++ compiler supporting C++20. We test GCC 12 or better, LLVM 14 or better and Microsoft Visual Studio 2022.

## Installation

Binary packages for the following systems are currently available:

[![Packaging status](https://repology.org/badge/vertical-allrepos/ada.svg)](https://repology.org/project/ada/versions)

## Quick Start

Linux or macOS users might follow the following instructions if they have a recent C++ compiler installed and a standard utility (`wget`)


1. Pull the library in a directory
   ```
   wget https://github.com/ada-url/ada/releases/download/v3.0.0/ada.cpp
   wget https://github.com/ada-url/ada/releases/download/v3.0.0/ada.h
   ```
2. Create a new file named `demo.cpp` with this content:
   ```C++
    #include "ada.cpp"
    #include "ada.h"
    #include <iostream>

    int main(int, char *[]) {
      auto url = ada::parse("https://www.google.com");
      if (!url) {
        std::cout << "failure" << std::endl;
        return EXIT_FAILURE;
      }
      url->set_protocol("http");
      std::cout << url->get_protocol() << std::endl;
      std::cout << url->get_host() << std::endl;
      return EXIT_SUCCESS;
    }
   ```
3. Compile
   ```
   c++ -std=c++20 -o demo demo.cpp
   ```
4. `./demo`

   ```
   http:
   www.google.com
   ```

## Bindings of Ada

The following libraries are maintained by the Ada team and available under [Ada GitHub organization](https://github.com/ada-url).

- [Rust](https://github.com/ada-url/rust): Rust bindings for Ada
- [Go](https://github.com/ada-url/goada): Go bindings for Ada
- [Python](https://github.com/ada-url/python): Python bindings for Ada

### Community maintained

- [R](https://github.com/schochastics/adaR): R wrapper for Ada
- [PHP](https://github.com/lnear-dev/ada-url): PHP Wrapper for Ada URL
- [LuaJIT](https://github.com/bungle/lua-resty-ada): LuaJIT FFI bindings for Ada
- [Zig](https://github.com/braheezy/ada-zig): Unofficial Zig bindings for Ada
- [Python](https://github.com/TkTech/can_ada): Python bindings for Ada
- [React Native](https://github.com/KusStar/react-native-fast-url): A Fast URL and URLSearchParams polyfill for React Native.
- [D](https://github.com/kassane/ada-d): D bindings for Ada, `@nogc`, `nothrow` and `@safe` compat.
- [Nim](https://github.com/ferus-web/nim-ada): High-level Nim abstraction over Ada, uses ORC move semantics to safely and efficiently handle memory.

## Usage

Ada supports two types of URL instances, `ada::url` and `ada::url_aggregator`. The usage is
the same in either case: we have an parsing function template `ada::parse` which can return
either a result of type `ada::result<ada::url>` or of type `ada::result<ada::url_aggregator>`
depending on your needs. The `ada::url_aggregator` class is smaller and it is backed by a precomputed
serialized URL string. The `ada::url` class is made of several separate strings for the various
components (path, host, and so forth).

### Parsing & Validation

- Parse and validate a URL from an ASCII or a valid UTF-8 string.

```cpp
auto url = ada::parse<ada::url_aggregator>("https://www.google.com");
if (url) { /* URL is valid */ }
```

After calling 'parse', you *must* check that the result is valid before
accessing it when you are not sure that it will succeed. The following
code is unsafe:

```cpp
auto> url = ada::parse<ada::url_aggregator>("some bad url");
url->get_href();
```

For simplicity, in the examples below, we skip the check because
we know that parsing succeeds. All strings are assumed to be valid
UTF-8 strings.

## Examples

## URL Parser

```c++
auto url = ada::parse<ada::url_aggregator>("https://www.google.com");

url->set_username("username"); // Update credentials
url->set_password("password");
// ada->get_href() will return "https://username:password@www.google.com/"

url->set_protocol("wss"); // Update protocol
// url->get_protocol() will return "wss:"

url->set_host("github.com"); // Update host
// url->get_host() will return "github.com"

url->set_port("8080"); // Update port
// url->get_port() will return "8080"

url->set_pathname("/my-super-long-path"); // Update pathname
// url->get_pathname() will return "/my-super-long-path"

url->set_search("target=self"); // Update search
// url->get_search() will return "?target=self"

url->set_hash("is-this-the-real-life"); // Update hash/fragment
// url->get_hash() will return "#is-this-the-real-life"
```

### URL Search Params

```cpp
ada::url_search_params search_params("a=b&c=d&e=f");
search_params.append("g=h");

search_params.get("g");  // will return "h"

auto keys = search_params.get_keys();
while (keys.has_next()) {
  auto key = keys.next();  // "a", "c", "e", "g"
}
```

### URLPattern

Our implementation doesn't provide a regex engine and leaves the decision of choosing the right engine to the user.
This is done as a security measure since the default std::regex engine is not safe and open to DDOS attacks.
Runtimes like Node.js and Cloudflare Workers use the V8 regex engine, which is safe and performant.

```cpp
// Define a regex engine that conforms to the following interface
// For example we will use v8 regex engine

class v8_regex_provider {
 public:
  v8_regex_provider() = default;
  using regex_type = v8::Global<v8::RegExp>;
  static std::optional<regex_type> create_instance(std::string_view pattern,
                                                   bool ignore_case);
  static std::optional<std::vector<std::optional<std::string>>> regex_search(
      std::string_view input, const regex_type& pattern);
  static bool regex_match(std::string_view input, const regex_type& pattern);
};

// Define a URLPattern
auto pattern = ada::parse_url_pattern<v8_regex_provider>("/books/:id(\\d+)", "https://example.com");

// Check validity
if (!pattern) { return EXIT_FAILURE; }

// Match a URL
auto match = pattern->match("https://example.com/books/123");

// Test a URL
auto matched = pattern->test("https://example.com/books/123");
```

### C wrapper

See the file `include/ada_c.h` for our C interface. We expect ASCII or UTF-8 strings.

```C
#include "ada_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

static void ada_print(ada_string string) {
  printf("%.*s\n", (int)string.length, string.data);
}

int main(int c, char *arg[] ) {
  const char* input =
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists";
  ada_url url = ada_parse(input, strlen(input));
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_print(ada_get_href(url)); // prints https://username:password@host:8080/pathname?query=true#hash-exists
  ada_print(ada_get_protocol(url)); // prints https:
  ada_print(ada_get_username(url)); // prints username
  ada_set_href(url, "https://www.yagiz.co", strlen("https://www.yagiz.co"));  
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_set_hash(url, "new-hash", strlen("new-hash"));
  ada_set_hostname(url, "new-host", strlen("new-host"));
  ada_set_host(url, "changed-host:9090", strlen("changed-host:9090"));
  ada_set_pathname(url, "new-pathname", strlen("new-pathname"));
  ada_set_search(url, "new-search", strlen("new-search"));
  ada_set_protocol(url, "wss", 3);  
  ada_print(ada_get_href(url)); // will print wss://changed-host:9090/new-pathname?new-search#new-hash

  // Manipulating search params
  ada_string search = ada_get_search(url);
  ada_url_search_params search_params =
      ada_parse_search_params(search.data, search.length);
  ada_search_params_append(search_params, "a", 1, "b", 1);
  ada_owned_string result = ada_search_params_to_string(search_params);
  ada_set_search(url, result.data, result.length);
  ada_free_owned_string(result);
  ada_free_search_params(search_params);

  ada_free(url);
  return EXIT_SUCCESS;
}
```

When linking against the ada library from C++, be minding that ada requires access to the standard
C++ library. E.g., you may link with the C++ compiler.

E.g., if you grab our single-header C++ files (`ada.cpp` and `ada.h`), as well as the C header (`ada_c.h`),
you can often compile a C program (`demo.c`) as follows under Linux/macOS systems:

```
c++ -c ada.cpp -std=c++20
cc -c demo.c
c++ demo.o ada.o -o cdemo
./cdemo
```

### Command-line interface

For more information about command-line options, please refer to the [CLI documentation](docs/cli.md).

### CMake dependency

See the file `tests/installation/CMakeLists.txt` for an example of how you might use ada from your own
CMake project, after having installed ada on your system.

## Contributing

Contributors are encouraged to read our [AI Tool Policy](AI_USAGE_POLICY.md).


### Building

Ada uses cmake as a build system, but also supports Bazel. It's recommended you to run the following 
commands to build it locally.

Without tests:

- **Build**: `cmake -B build && cmake --build build`

With tests (requires git):

- **Build**: `cmake -B build -DADA_TESTING=ON && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

With tests (requires available local packages):

- **Build**: `cmake -B build -DADA_TESTING=ON -D CPM_USE_LOCAL_PACKAGES=ON && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

### Build options

Ada provides several CMake options to customize the build:

- `ADA_USE_SIMDUTF`: Enables SIMD-accelerated Unicode processing via simdutf (default: OFF)
- `ADA_USE_SYSTEM_SIMDUTF`: Use system-installed simdutf via CMake config (default: OFF)

Windows users need additional flags to specify the build configuration, e.g. `--config Release`.

The project can also be built via docker using default docker file of repository with following commands.

`docker build -t ada-builder . && docker run --rm -it -v ${PWD}:/repo ada-builder`

### Amalgamation

You may amalgamate all source files into only two files (`ada.h` and `ada.cpp`) by typing executing the Python
3 script `singleheader/amalgamate.py`. By default, the files are created in the `singleheader` directory.

### License

This code is made available under the Apache License 2.0 as well as the MIT license.

Our tests include third-party code and data. The benchmarking code includes third-party code: it is provided for research purposes only and not part of the library.


### Further reading

* Yagiz Nizipli, Daniel Lemire, [Parsing Millions of URLs per Second](https://doi.org/10.1002/spe.3296), Software: Practice and Experience 54(5) May 2024.

## Stars


[![Star History Chart](https://api.star-history.com/svg?repos=ada-url/ada&type=Date)](https://www.star-history.com/#ada-url/ada&Date)
