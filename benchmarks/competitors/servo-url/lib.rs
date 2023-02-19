use url::Url;
use std::ffi::{CStr, CString};
use libc::c_char;

extern crate url;
extern crate libc;

#[repr(C)]
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
pub extern "C" fn parse_url(raw_input: *const c_char) -> StandardUrl {
  let input_str = unsafe { CStr::from_ptr(raw_input) };
  let input = input_str.to_str().unwrap();
  let result = Url::parse(input).unwrap();

  let scheme = CString::new(result.scheme()).unwrap().into_raw();
  let username = CString::new(result.username()).unwrap().into_raw();
  let password = CString::new(result.password().unwrap_or("")).unwrap().into_raw();
  let host = CString::new(result.host_str().unwrap_or("")).unwrap().into_raw();
  let query = CString::new(result.query().unwrap_or("")).unwrap().into_raw();
  let fragment = CString::new(result.fragment().unwrap_or("")).unwrap().into_raw();
  let path = CString::new(result.path().to_string()).unwrap().into_raw();
  let href = CString::new(result.as_str()).unwrap().into_raw();

  StandardUrl {
      port: result.port().unwrap_or(0),
      scheme,
      username,
      password,
      host,
      query,
      fragment,
      path,
      href,
  }
}