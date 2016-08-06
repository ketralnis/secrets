use std::ffi::{CStr, CString, NulError};

use libc;

quick_error! {
    #[derive(Debug)]
    pub enum GetpassError {
        Nul(err: NulError) {from()}
    }
}

pub fn get_pass(prompt: &str) -> Result<Vec<u8>, GetpassError> {
    let prompt = try!(CString::new(prompt));
    let mut ret: Vec<u8> = Vec::new();

    unsafe {
        let pass = getpass(prompt.as_ptr());
        let bytes = CStr::from_ptr(pass).to_bytes();
        ret.extend_from_slice(bytes);

        // zero out the static buffer stored in getpass
        bzero(pass as *mut libc::c_void, bytes.len());
    };

    return Ok(ret);
}

extern "C" {
  fn getpass(prompt: *const libc::c_char) -> *const libc::c_char;
  fn bzero(ptr: *mut libc::c_void, len: libc::size_t) -> libc::c_void;
}
