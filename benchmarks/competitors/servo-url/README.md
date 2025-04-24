## Servo URL FFI

This folder includes FFI bindings for servo/url.

### Links

- https://github.com/eqrion/cbindgen/blob/master/docs.md
- https://gist.github.com/zbraniecki/b251714d77ffebbc73c03447f2b2c69f
- https://github.com/Michael-F-Bryan/rust-ffi-guide/blob/master/book/setting_up.md

### Building

- Generating cbindgen output
  - Install dependencies with `brew install cbindgen`
  - Generate with `cbindgen --config cbindgen.toml --crate servo-url --output servo_url.h`
- Building
  - Run with `cargo build --release`
