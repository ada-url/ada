use url::Url;
use std::ffi::{CString};
use std::{slice, ptr};
use libc::{c_char};

extern crate url;
extern crate libc;

pub struct StandardUrl {
  pub port: u16,
  pub scheme: *mut c_char,
  pub username: *mut c_char,
  pub password: *mut c_char,
  pub host: *mut c_char,
  pub query: *mut c_char,
  pub fragment: *mut c_char,
  pub path: *mut c_char,
  pub href: *mut c_char,
}

#[no_mangle]
pub extern "C" fn parse_url(raw_input: *const c_char, raw_input_length: usize) -> *mut StandardUrl {
  let input = unsafe {
    std::str::from_utf8_unchecked(slice::from_raw_parts(raw_input as *const u8, raw_input_length))
  };
  let result = Url::parse(input).unwrap();

  let scheme = CString::new(result.scheme()).unwrap().into_raw();
  let username = CString::new(result.username()).unwrap().into_raw();
  let password = CString::new(result.password().unwrap_or("")).unwrap().into_raw();
  let host = CString::new(result.host_str().unwrap_or("")).unwrap().into_raw();
  let query = CString::new(result.query().unwrap_or("")).unwrap().into_raw();
  let fragment = CString::new(result.fragment().unwrap_or("")).unwrap().into_raw();
  let path = CString::new(result.path().to_string()).unwrap().into_raw();
  let href = CString::new(result.as_str()).unwrap().into_raw();

  let mut out = StandardUrl {
      port: result.port().unwrap_or(0),
      scheme,
      username,
      password,
      host,
      query,
      fragment,
      path,
      href,
  };

  ptr::addr_of_mut!(out)
}

#[no_mangle]
pub extern "C" fn free_standard_url(raw: *mut StandardUrl) {
  drop(unsafe { Box::from_raw(raw) })
}
