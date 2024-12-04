#include "ada.h"

#include <optional>
#include <string>

namespace ada {

namespace url_pattern {

std::optional<std::string> canonicalize_protocol(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.
  if (auto dummy_url = ada::parse<ada::url_aggregator>(
          std::string(input) + "://dummy.test", nullptr)) {
    // Return dummyURL’s scheme.
    return std::string(dummy_url->get_protocol());
  }
  // If parseResult is failure, then throw a TypeError.
  return std::nullopt;
}

std::optional<std::string> canonicalize_username(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  // Set the username given dummyURL and value.
  if (!url->set_username(input)) {
    return std::nullopt;
  }
  // Return dummyURL’s username.
  return std::string(url->get_username());
}

std::optional<std::string> canonicalize_password(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set the password given dummyURL and value.
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);

  ADA_ASSERT_TRUE(url.has_value());
  if (!url->set_password(input)) {
    return std::nullopt;
  }
  // Return dummyURL’s password.
  return std::string(url->get_password());
}

std::optional<std::string> canonicalize_hostname(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // with dummyURL as url and hostname state as state override.
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  // if (!isValidHostnameInput(hostname)) return kj::none;
  if (!url->set_hostname(input)) {
    // If parseResult is failure, then throw a TypeError.
    return std::nullopt;
  }
  const auto hostname = url->get_hostname();
  // Return dummyURL’s host, serialized, or empty string if it is null.
  return hostname.empty() ? "" : std::string(hostname);
}

std::optional<std::string> canonicalize_ipv6_hostname(std::string_view input) {
  // Optimization opportunity: Use lookup table to speed up checking
  if (std::ranges::all_of(input, [](char c) {
        return c == '[' || c == ']' || c == ':' ||
               ada::unicode::is_ascii_hex_digit(c);
      })) {
    return std::nullopt;
  }
  // Append the result of running ASCII lowercase given code point to the end of
  // result.
  auto hostname = std::string(input);
  ada::unicode::to_lower_ascii(hostname.data(), hostname.size());
  return hostname;
}

std::optional<std::string> canonicalize_port(std::string_view port_value,
                                             std::string_view protocol) {
  // If portValue is the empty string, return portValue.
  if (port_value.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // If protocolValue was given, then set dummyURL’s scheme to protocolValue.
  // Let parseResult be the result of running basic URL parser given portValue
  // with dummyURL as url and port state as state override.
  auto url = ada::parse<ada::url_aggregator>(
      std::string(protocol) + "://dummy.test", nullptr);
  if (url && url->set_port(port_value)) {
    // Return dummyURL’s port, serialized, or empty string if it is null.
    return std::string(url->get_port());
  }
  // If parseResult is failure, then throw a TypeError.
  return std::nullopt;
}

std::optional<std::string> canonicalize_pathname(std::string_view input) {
  // If value is the empty string, then return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let leading slash be true if the first code point in value is U+002F (/)
  // and otherwise false.
  const bool leading_slash = input.starts_with("/");
  // Let modified value be "/-" if leading slash is false and otherwise the
  // empty string.
  const auto modified_value = leading_slash ? "" : "/-";
  const auto full_url =
      std::string("fake://fake-url") + modified_value + std::string(input);
  if (auto url = ada::parse<ada::url_aggregator>(full_url, nullptr)) {
    const auto pathname = url->get_pathname();
    // If leading slash is false, then set result to the code point substring
    // from 2 to the end of the string within result.
    return leading_slash ? std::string(pathname)
                         : std::string(pathname.substr(2));
  }
  // If parseResult is failure, then throw a TypeError.
  return std::nullopt;
}

std::optional<std::string> canonicalize_opaque_pathname(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s path to the empty string.
  // Let parseResult be the result of running URL parsing given value with
  // dummyURL as url and opaque path state as state override.
  if (auto url = ada::parse<ada::url_aggregator>("fake:" + std::string(input),
                                                 nullptr)) {
    // Return the result of URL path serializing dummyURL.
    return std::string(url->get_pathname());
  }
  // If parseResult is failure, then throw a TypeError.
  return std::nullopt;
}

std::optional<std::string> canonicalize_search(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s query to the empty string.
  // Let parseResult be the result of running basic URL parser given value with
  // dummyURL as url and query state as state override.
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_search(input);
  const auto search = url->get_search();
  // Return dummyURL’s query.
  return !search.empty() ? std::string(search.substr(1)) : "";
}

std::optional<std::string> canonicalize_hash(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s fragment to the empty string.
  // Let parseResult be the result of running basic URL parser given value with
  // dummyURL as url and fragment state as state override.
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_hash(input);
  const auto hash = url->get_hash();
  if (hash.empty()) {
    return "";
  }
  // Return dummyURL’s fragment.
  return std::string(hash.substr(1));
}

}  // namespace url_pattern

URLPattern::Component::Component(std::string_view pattern_,
                                 std::string_view regex_,
                                 const std::vector<std::string>& names_) {
  // TODO: Implement this
  pattern = pattern_;
  regex = regex_;
  names = std::move(names_);
}

std::optional<URLPattern::Result> URLPattern::exec(
    std::optional<Input> input, std::optional<std::string> base_url) {
  // TODO: Implement this
  return std::nullopt;
}

bool URLPattern::test(std::optional<Input> input,
                      std::optional<std::string_view> base_url) {
  // TODO: Implement this
  return false;
}

}  // namespace ada
