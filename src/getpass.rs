use std::ffi::{CStr, CString};

use libc;

extern "C" {
  fn getpass(prompt: *const libc::c_char) -> *const libc::c_char;
  fn bzero(ptr: *mut libc::c_void, len: libc::size_t) -> libc::c_void;
}

pub fn get_pass(prompt: &'static str) -> Vec<u8> {
    // panics on prompts that contain null bytes, but since they are 'static
    // that would be due to a bug
    let mut prompt = prompt.as_bytes().to_vec();
    prompt.extend_from_slice(&(b": ")[..]);
    let cprompt = CString::new(prompt).unwrap();

    let mut ret: Vec<u8> = Vec::new();

    unsafe {
        let pass = getpass(cprompt.as_ptr());
        let bytes = CStr::from_ptr(pass).to_bytes();

        // getpass(1) uses a static buffer, so copy the entered password out
        ret.extend_from_slice(bytes);

        // zero out the static buffer stored in getpass
        bzero(pass as *mut libc::c_void, bytes.len());
    };

    return ret;
}
