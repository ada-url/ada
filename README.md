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

- Get/Update credentials

```cpp
ada::url url = ada::parse("https://www.google.com");
ada::set_username(url, "username");
ada::set_password(url, "password");
// Url is now: "https://username:password@www.google.com"
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
