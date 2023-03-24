# Ada
![OpenSSF Scorecard Badge](https://api.securityscorecards.dev/projects/github.com/ada-url/ada/badge)
[![Ubuntu 22.04](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu.yml)
[![VS17-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio.yml)
[![VS17-clang-CI](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/visual_studio_clang.yml)
[![Ubuntu s390x (GCC 11)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml/badge.svg)](https://github.com/ada-url/ada/actions/workflows/ubuntu-s390x.yml)

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from the
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

## Requirements

- A recent C++ compiler supporting C++17. We test GCC 9 or better, LLVM 10 or better and Microsoft Visual Studio 2022.
- We use [ICU](https://icu.unicode.org) when it is available.

## Usage

Ada supports two types of URL instances, `ada:url` and `ada:url_aggregator`. The usage is
the same in either case: we have an parsing function template `ada::parse` which can return
either a result of type `ada::result<ada:url>` or of type `ada::result<ada:url_aggregator>`
depending on your needs. The `ada:url_aggregator` class is smaller and it is backed by a precomputed
serialized URL string. The `ada:url` class is made of several separate strings for the various
components (path, host, and so forth).

### Examples

- Parse and validate a URL

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
if(url) { /* URL is valid */ }
```

After calling 'parse', you *must* check that the result is valid before
accessing it when you are not sure that it will succeed. The following
code is unsafe:

```cpp
ada::result url = ada::parse("some bad url");
url->get_href();
```

You should do...

```cpp
ada::result url = ada::parse("some bad url");
if(url) {
  // next line is now safe:
  url->get_href();
} else {
  // report a parsing failure
}
```

For simplicity, in the examples below, we skip the check because
we know that parsing succeeds.

- Get/Update credentials

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_username("username");
url->set_password("password");
// ada->get_href() will return "https://username:password@www.google.com/"
```

- Get/Update Protocol

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_protocol("wss");
// url->get_protocol() will return "wss:"
// url->get_href() will return "wss://www.google.com/"
```

- Get/Update host

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_host("github.com");
// url->get_host() will return "github.com"
// you can use `url.set_hostname` depending on your usage.
```

- Get/Update port

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_port("8080");
// url->get_port() will return "8080"
```

- Get/Update pathname

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_pathname("/my-super-long-path")
// url->get_pathname() will return "/my-super-long-path"
```

- Get/Update search/query

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_search("target=self");
// url->get_search() will return "?target=self"
```

- Get/Update hash/fragment

```cpp
ada::result<ada:url> url = ada::parse("https://www.google.com");
url->set_hash("is-this-the-real-life");
// url->get_hash() will return "#is-this-the-real-life"
```


### CMake dependency

See the file `tests/installation/CMakeLists.txt` for an example of how you might use ada from your own CMake project, after having installed ada on your system.

## Contributing

### Building

Ada uses cmake as a build system. It's recommended you to run the following commands to build it locally.

- **Build**: `cmake -B build && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

Windows users need additional flags to specify the build configuration, e.g. `--config Release`.

Project can also be built via docker using default docker file of repository with following commands.

`docker build -t ada-builder . && docker run --rm -it -v ${PWD}:/repo ada-builder`

### Installing ICU

For macOS, you may install it with [brew](https://brew.sh) using `brew install icu4c`. Linux users may install ICU according to the their distribution: under Ubuntu, the command is `apt-get install -y libicu-dev`.

### Amalgamation

You may amalgamate all source files into only two files (`ada.h` and `ada.cpp`) by typing executing the Python 3 script `singleheader/amalgamate.py`. By default, the files are created in the `singleheader` directory.
