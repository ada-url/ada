use url::Url;
use std::slice;
use libc::{c_char, size_t};

extern crate url;
extern crate libc;

#[no_mangle]
pub unsafe extern "C" fn parse_url(raw_input: *const c_char, raw_input_length: size_t) -> *mut Url {
  let input = std::str::from_utf8_unchecked(slice::from_raw_parts(raw_input as *const u8, raw_input_length));
  // This code would assume that the URL is parsed successfully:
  // let result = Url::parse(input).unwrap();
  // Box::into_raw(Box::new(result))
  // But we might get an invalid input. So we want to return null in case of
  // error. We can do it in such a manner:
  match Url::parse(input) {
    Ok(result) => Box::into_raw(Box::new(result)),
    Err(_) => std::ptr::null_mut(),
  }
}

#[no_mangle]
pub unsafe extern "C" fn parse_url_to_href(raw_input: *const c_char, raw_input_length: size_t) -> *const c_char {
  let input = std::str::from_utf8_unchecked(slice::from_raw_parts(raw_input as *const u8, raw_input_length));
  match Url::parse(input) {
    Ok(result) => std::ffi::CString::new(result.as_str()).unwrap().into_raw(),
    Err(_) => std::ptr::null_mut(),
  }
}

#[no_mangle]
pub unsafe extern "C" fn free_url(raw: *mut Url) {
  if raw.is_null() {
    return;
  }

  drop(Box::from_raw(raw))
}

#[no_mangle]
pub unsafe extern fn free_string(ptr: *const c_char) {
    // Take the ownership back to rust and drop the owner
    let _ = std::ffi::CString::from_raw(ptr as *mut _);
}
