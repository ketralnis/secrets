use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::io::FromRawFd;

use rpassword;

pub enum PasswordSource {
    Password(String),
    Env(String),
    File(String),
    Fd(i32),
    Prompt,
}

quick_error! {
    #[derive(Debug)]
    pub enum PasswordError {
        VarError(err: env::VarError) { from() }
        Io(err: io::Error) { from() }
    }
}

pub fn validate_password_source(source: String) -> Result<(), String> {
    return parse_password_source(&source).map(|_| ())
}

pub fn parse_password_source(source: &str) -> Result<PasswordSource, String> {
    let rest = || {
        let v: Vec<&str> = source.splitn(2, ":").collect();
        if v.len() == 2 {
            v[1].to_string()
        } else {
            "".to_string()
        }
    };

    if source.starts_with("pass:") {
        Ok(PasswordSource::Password(rest()))
    } else if source.starts_with("env:") {
        Ok(PasswordSource::Env(rest()))
    } else if source.starts_with("file:") {
        Ok(PasswordSource::File(rest()))
    } else if source.starts_with("fd:") {
        let fd_str = rest();
        let fd = try!(fd_str.parse::<i32>().map_err(|_| "not a number"));
        Ok(PasswordSource::Fd(fd))
    } else if source == "prompt" {
        Ok(PasswordSource::Prompt)
    } else {
        Err("unknown password source".to_string())
    }
}

pub fn evaluate_password_source(source: PasswordSource) -> Result<String, PasswordError> {
    match source {
        PasswordSource::Password(x) => Ok(x),
        PasswordSource::Env(key) => {
            let value = try!(env::var(key));
            Ok(value)
        }
        PasswordSource::File(fname) => {
            let mut f = try!(File::open(fname));
            let mut s = String::new();
            try!(f.read_to_string(&mut s));
            Ok(s)
        }
        PasswordSource::Fd(fd) => {
            let mut f = unsafe {
                File::from_raw_fd(fd)
            };
            let mut s = String::new();
            try!(f.read_to_string(&mut s));
            Ok(s)
        }
        PasswordSource::Prompt => {
            try!(io::stderr().write(b"password:"));
            let val = try!(rpassword::read_password());
            Ok(val)
        }
    }
}
