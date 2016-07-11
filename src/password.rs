use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::process::Command;
use std::string;

use rpassword;
use tempfile;

pub enum PasswordSource {
    Password(String),
    Env(String),
    File(String),
    Fd(i32),
    Prompt,
    Edit(Option<String>),
}

quick_error! {
    #[derive(Debug)]
    pub enum PasswordError {
        VarError(err: env::VarError) {from()}
        Io(err: io::Error) {from()}
        Utf8(err: string::FromUtf8Error) {from()}
        Editor(what: &'static str) {}
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
    } else if source == "edit" {
        Ok(PasswordSource::Edit(None))
    } else if source.starts_with("edit:") {
        Ok(PasswordSource::Edit(Some(rest())))
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
        },
        PasswordSource::Edit(editor) => {
            let editor = match editor {
                None => {
                    try!(env::var("EDITOR")
                        .map_err(|_| PasswordError::Editor(
                            "editor not specified and $EDITOR not set")))
                },
                Some(x) => x
            };
            let tfile = try!(tempfile::NamedTempFile::new());
            try!(tfile.sync_all());
            let md = try!(tfile.metadata());
            let mut permissions = md.permissions();
            permissions.set_mode(0o600);
            try!(fs::set_permissions(tfile.path(), permissions));

            // use the shell to execute the editor
            let tfile_path = try!(tfile.path().to_str()
                .ok_or(PasswordError::Editor("couldn't destr the tempfile name?")));
            let command = format!("{} {}", editor, tfile_path);
            let mut child = try!(
                Command::new("/bin/sh")
                .arg("-e")
                .arg(command)
                .spawn());
            let ecode = try!(child.wait());
            if !ecode.success() {
                return Err(PasswordError::Editor("editor failed"))
            }
            let mut reread = try!(File::open(tfile.path()));
            let mut inputted: Vec<u8> = Vec::new();
            try!(reread.read_to_end(&mut inputted));

            if inputted[inputted.len()-1] == b'\n' {
                // editors add a newline to the end which the user probably
                // doesn't intend
                let newlen = inputted.len()-1;
                inputted.truncate(newlen);
            }

            let password = try!(String::from_utf8(inputted));
            Ok(password)
        }

    }
}
