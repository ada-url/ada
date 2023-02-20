use url::Url;
use std::slice;
use libc::{c_char, size_t};

extern crate url;
extern crate libc;

#[no_mangle]
pub unsafe extern "C" fn parse_url(raw_input: *const c_char, raw_input_length: size_t) -> *mut Url {
  let input = std::str::from_utf8_unchecked(slice::from_raw_parts(raw_input as *const u8, raw_input_length));
  let result = Url::parse(input).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub unsafe extern "C" fn free_url(raw: *mut Url) {
  if raw.is_null() {
    return;
  }

  drop(Box::from_raw(raw))
}
