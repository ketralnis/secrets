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

use tempfile;

use getpass;

pub enum PasswordSource {
    Password(String),
    Stdin,
    Env(String),
    File(String),
    Fd(i32),
    Prompt,
    Edit(Option<String>),
}

#[derive(Debug, Fail)]
pub enum PasswordError {
    #[fail(display = "VarError({})", _0)]
    VarError(#[fail(cause)] env::VarError),

    #[fail(display = "Io({})", _0)]
    Io(#[fail(cause)] io::Error),

    #[fail(display = "Utf8({})", _0)]
    Utf8(#[fail(cause)] string::FromUtf8Error),

    #[fail(display = "Editor({})", _0)]
    Editor(String),
}

simple_err_impl!(PasswordError, VarError, env::VarError);
simple_err_impl!(PasswordError, Io, io::Error);
simple_err_impl!(PasswordError, Utf8, string::FromUtf8Error);

pub fn validate_password_source<T: AsRef<str>>(
    source: T,
) -> Result<(), String> {
    parse_password_source(source.as_ref()).map(|_| ())
}

pub fn parse_password_source(source: &str) -> Result<PasswordSource, String> {
    let rest = || {
        let v: Vec<&str> = source.splitn(2, ':').collect();
        if v.len() == 2 {
            v[1].to_string()
        } else {
            "".to_string()
        }
    };

    if source.starts_with("pass:") {
        Ok(PasswordSource::Password(rest()))
    } else if source == "stdin" {
        Ok(PasswordSource::Stdin)
    } else if source.starts_with("env:") {
        Ok(PasswordSource::Env(rest()))
    } else if source.starts_with("file:") {
        Ok(PasswordSource::File(rest()))
    } else if source.starts_with("fd:") {
        let fd_str = rest();
        let fd = fd_str.parse::<i32>().map_err(|_| "not a number")?;
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

pub fn evaluate_password_source(
    source: PasswordSource,
    prompt: &'static str,
) -> Result<String, PasswordError> {
    match source {
        PasswordSource::Password(x) => Ok(x),
        PasswordSource::Env(key) => {
            let value = env::var(key)?;
            Ok(value)
        }
        PasswordSource::File(fname) => {
            let mut f = File::open(fname)?;
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        }
        PasswordSource::Stdin => {
            let mut f = io::stdin();
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        }
        PasswordSource::Fd(fd) => {
            let mut f = unsafe { File::from_raw_fd(fd) };
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        }
        PasswordSource::Prompt => {
            let val = getpass::get_pass(prompt);
            let password = String::from_utf8(val)?;
            Ok(password)
        }
        PasswordSource::Edit(editor) => {
            let val = edit(editor, &b""[..])?;
            let password = String::from_utf8(val)?;
            Ok(password)
        }
    }
}

pub fn edit(
    chosen_editor: Option<String>,
    initial_contents: &[u8],
) -> Result<Vec<u8>, PasswordError> {
    let editor = if chosen_editor.is_some() {
        chosen_editor.unwrap()
    } else if env::var("VISUAL").is_ok() {
        env::var("VISUAL").unwrap()
    } else if env::var("EDITOR").is_ok() {
        env::var("EDITOR").unwrap()
    } else {
        return Err(PasswordError::Editor(
            "editor not specified and \
             $VISUAL/$EDITOR unset"
                .to_string(),
        ));
    };

    let mut tfile = tempfile::NamedTempFile::new()?;

    tfile.write_all(initial_contents)?;
    tfile.sync_all()?;

    let md = tfile.metadata()?;
    let mut permissions = md.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(tfile.path(), permissions)?;

    // use the shell to execute the editor
    let tfile_path = tfile.path().to_str().ok_or_else(|| {
        PasswordError::Editor(
            "couldn't de-str the tempfile \
             name?"
                .to_string(),
        )
    })?;
    let command = format!("{} {}", editor, tfile_path);
    let mut child = Command::new("/bin/sh").arg("-c").arg(command).spawn()?;
    debug!("spawned editor to PID {}", child.id());

    let ecode = child.wait()?;
    debug!("editor returned with {:?}", ecode.code());

    if !ecode.success() {
        return Err(PasswordError::Editor(format!(
            "editor failed with {:?}",
            ecode.code()
        )));
    }
    let mut reread = File::open(tfile.path())?;
    let mut inputted: Vec<u8> = Vec::new();
    reread.read_to_end(&mut inputted)?;

    if inputted[inputted.len() - 1] == b'\n' {
        // editors add a newline to the end which the user probably
        // doesn't intend
        let newlen = inputted.len() - 1;
        inputted.truncate(newlen);
    }
    Ok(inputted)
}
