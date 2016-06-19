use std::io;
use std::io::Write;
use std::io::Read;

use regex;

pub fn validate_host(name: &str, value: &str)
        -> Result<(), String> {
    return re_validator(name, r"[a-zA-Z0-9.-]+(:[0-9]{1,5})?", value);
}

pub fn re_validator(name: &str, re_expr: &'static str, value: &str)
        -> Result<(), String> {
    let re = regex::Regex::new(&re_expr).unwrap();
    if re.is_match(value) {
        return Ok(())
    } else {
        return Err(format!("{}: {} doesn't match /{}/",
                           name, value, re_expr))
    }
}

pub fn hex(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    return strs.join("")
}

pub fn prompt_yn(prompt: &str) -> io::Result<bool> {
    let mut stderr = io::stderr();
    let stdin = io::stdin();
    let mut buff = String::with_capacity(5);

    loop {
        try!(stderr.write(prompt.as_bytes()));
        try!(stderr.flush());

        buff.clear();
        try!(stdin.read_line(&mut buff));

        match buff.as_str().trim_right() {
            "Y" | "y" | "yes" => return Ok(true),
            "N" | "n" | "no" => return Ok(false),
            _ => continue
        }
    }
}
