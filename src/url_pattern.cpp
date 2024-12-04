#include "ada.h"

#include <optional>
#include <string>

namespace ada {

namespace url_pattern {

std::optional<std::string> canonicalize_username(std::string_view input) {
  if (input.size()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  if (!url->set_username(input)) {
    return std::nullopt;
  }
  return std::string(url->get_username());
}

std::optional<std::string> canonicalize_password(std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);

  ADA_ASSERT_TRUE(url.has_value());
  if (!url->set_password(input)) {
    return std::nullopt;
  }
  return std::string(url->get_password());
}

std::optional<std::string> canonicalize_hostname(std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  // if (!isValidHostnameInput(hostname)) return kj::none;
  if (!url->set_hostname(input)) {
    return std::nullopt;
  }
  return std::string(url->get_hostname());
}

std::optional<std::string> canonicalize_ipv6_hostname(std::string_view input) {
  // Optimization opportunity: Use lookup table to speed up checking
  if (std::ranges::all_of(input, [](char c) {
        return c == '[' || c == ']' || c == ':' ||
               ada::unicode::is_ascii_hex_digit(c);
      })) {
    return std::nullopt;
  }
  // Optimization opportunity: Consider just moving value, rather than copying
  // it.
  return std::string(input);
}

std::optional<std::string> canonicalize_port(std::string_view input,
                                             std::string_view protocol) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>(
      std::string(protocol) + "://dummy.test", nullptr);
  if (url && url->set_port(input)) {
    return std::string(url->get_port());
  }
  return std::nullopt;
}

std::optional<std::string> canonicalize_pathname(std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  const bool leading_slash = input.starts_with("/");
  auto path_prefix = leading_slash ? "" : "/-";
  auto full_url =
      std::string("fake://fake-url") + path_prefix + std::string(input);
  if (auto url = ada::parse<ada::url_aggregator>(full_url, nullptr)) {
    const auto pathname = url->get_pathname();
    return leading_slash ? std::string(pathname)
                         : std::string(pathname.substr(2));
  }
  return std::nullopt;
}

std::optional<std::string> canonicalize_opaque_pathname(
    std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  if (auto url = ada::parse<ada::url_aggregator>("fake:" + std::string(input),
                                                 nullptr)) {
    return std::string(url->get_pathname());
  }
  return std::nullopt;
}

std::optional<std::string> canonicalize_search(std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_search(input);
  const auto search = url->get_search();
  return !search.empty() ? std::string(search.substr(1)) : "";
}

std::optional<std::string> canonicalize_hash(std::string_view input) {
  if (input.empty()) [[unlikely]] {
    return "";
  }
  auto url = ada::parse<ada::url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_hash(input);
  const auto hash = url->get_hash();
  if (hash.empty()) {
    return "";
  }
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
