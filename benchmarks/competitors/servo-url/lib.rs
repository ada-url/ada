use url::Url;
use std::{slice, ptr};
use libc::c_char;

extern crate url;
extern crate libc;

pub struct StandardUrl {
  pub port: u16,
  pub scheme: String,
  pub username: String,
  pub password: String,
  pub host: String,
  pub query: String,
  pub fragment: String,
  pub path: String,
  pub href: String,
}

#[no_mangle]
pub extern "C" fn parse_url(raw_input: *const c_char, raw_input_length: usize) -> *mut StandardUrl {
  let input = unsafe {
    std::str::from_utf8_unchecked(slice::from_raw_parts(raw_input as *const u8, raw_input_length))
  };
  let result = Url::parse(input).unwrap();

  let mut out = StandardUrl {
      port: result.port().unwrap_or(0),
      scheme: result.scheme().to_string(),
      username: result.username().to_string(),
      password: result.password().unwrap_or("").to_string(),
      host: result.host_str().unwrap_or("").to_string(),
      query: result.query().unwrap_or("").to_string(),
      fragment: result.fragment().unwrap_or("").to_string(),
      path: result.path().to_string(),
      href: result.as_str().to_string(),
  };

  ptr::addr_of_mut!(out)
}

#[no_mangle]
pub extern "C" fn free_standard_url(raw: *mut StandardUrl) {
  drop(unsafe { Box::from_raw(raw) })
}
