use std::io;
use std::io::Write;

use regex;

pub fn validate_host(name: &str, value: &str) -> Result<(), String> {
    return re_validator(name, r"[a-zA-Z0-9.-]+(:[0-9]{1,5})?", value);
}

pub fn re_validator(name: &str,
                    re_expr: &'static str,
                    value: &str)
                    -> Result<(), String> {
    let re = regex::Regex::new(&re_expr).unwrap();
    if re.is_match(value) {
        return Ok(());
    } else {
        return Err(format!("{}: {} doesn't match /{}/", name, value, re_expr));
    }
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
            _ => continue,
        }
    }
}

pub fn constant_time_compare(actual: &[u8], expected: &[u8]) -> bool {
    let actual_len = actual.len();
    let expected_len = expected.len();
    let mut res = actual_len ^ expected_len;
    for x in 0..actual_len {
        res |= (actual[x] ^ expected[x % expected_len]) as usize;
    }
    return res == 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_constant_time_compare() {
        let compare = |actual: &str, expected: &str| {
            return constant_time_compare(&actual.as_bytes(),
                                         &expected.as_bytes());
        };
        assert_eq!(true, compare("abc", "abc"));
        assert_eq!(false, compare("abc", "ab"));
        assert_eq!(false, compare("ab", "abc"));
        assert_eq!(false, compare("ab", "aba"));
        assert_eq!(false, compare("abd", "abc"));
    }
}
