#ifndef ADA_ENCODING_TYPE_H
#define ADA_ENCODING_TYPE_H

namespace ada {

  /**
   * This specification defines three encodings with the same names as encoding schemes defined
   * in the Unicode standard: UTF-8, UTF-16LE, and UTF-16BE.
   *
   * @see https://encoding.spec.whatwg.org/#encodings
   */
  enum class encoding_type {
    UTF8,
    UTF_16LE,
    UTF_16BE,
  };

  ada_warn_unused std::string to_string(encoding_type type);

} // ada namespace

#endif // ADA_ENCODING_TYPE_H
