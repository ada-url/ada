# Ada 

Ada is a fast and spec-compliant URL parser written in C++.
Specification for URL parser can be found from 
[WHATWG](https://url.spec.whatwg.org/#url-parsing) website.

## Requirements

- A recent C++ compiler supporting C++17 (e.g., gcc 8 or better)
- [ICU](https://icu.unicode.org).

## Local Development

Ada uses cmake as a build system. It's recommended you to run the following commands to build it locally.

- **Build**: `cmake -B build && cmake --build build`
- **Test**: `ctest --output-on-failure --test-dir build`

## Usage

- Parse and validate a URL

```cpp
ada::url url = ada::parse("https://www.google.com");
// url.is_valid will return true
```

- Update a scheme

```cpp
ada::url url = ada::parse("https://www.google.com");
ada::set_scheme(url, "http");
// Url is now: "http://www.google.com"
```

- Update credentials

```cpp
ada::url url = ada::parse("https://www.google.com");
ada::set_username(url, "username");
ada::set_password(url, "password");
// Url is now: "https://username:password@www.google.com"
```

- Update hostname

```cpp
ada::url url = ada::parse("https://www.google.com");
ada::set_host("github.com");
// Url is now: "https://github.com"
```

- Update port

```cpp
ada::url url = ada::parse("https://www.google.com");
ada:set_port("8080");
// Url is now: "https://www.google.com:8080"
```

- Update pathname

```cpp
ada::url url = ada::parse("https://www.google.com");
ada:set_pathname("/my-super-long-path");
// Url is now: "https://www.google.com/my-super-long-path"
```

- Update search/query

```cpp
ada::url url = ada::parse("https://www.google.com");
ada:set_search("target=self");
// Url is now: "https://www.google.com?target=self"
```

- Update hash/fragment

```cpp
ada::url url = ada::parse("https://www.google.com");
ada:set_port("is-this-the-real-life");
// Url is now: "https://www.google.com#is-this-the-real-life"
```
