#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include <optional>

namespace ada {

  class Parser {

  public:
    Parser(std::string_view input, std::optional<ada::URL> optional_base_url, std::optional<ada::encoding_type> encoding, std::optional<ada::state> state);
    ada::URL getURL();

  private:
    void parseState();

    std::string_view input;
    std::string buffer;
    bool at_sign_seen = false;
    bool inside_brackets = false;
    bool password_token_seen = false;

    const char* pointer;

    ada::encoding_type encoding = ada::encoding_type::UTF8;
    ada::state state = SCHEME_START;
    std::optional<ada::state> state_override;

    ada::URL url;
    std::optional<ada::URL> base_url;
  }; // class Parser

}

#endif // ADA_PARSER_H
