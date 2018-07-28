use std::io;
use std::io::Write;

use chrono::{Local, TimeZone};
use regex;

#[macro_export]
macro_rules! simple_err_impl {
    ($root_type:ident, $variant_name:ident, $source_error:ty) => {
        impl From<$source_error> for $root_type {
            fn from(err: $source_error) -> Self {
                $root_type::$variant_name(err)
            }
        }
    };
}

pub fn validate_host(name: &str, value: &str) -> Result<(), String> {
    re_validator(name, r"[a-zA-Z0-9.-]+(:[0-9]{1,5})?", value)
}

pub fn re_validator(
    name: &str,
    re_expr: &'static str,
    value: &str,
) -> Result<(), String> {
    let re = regex::Regex::new(re_expr).unwrap();
    if re.is_match(value) {
        Ok(())
    } else {
        Err(format!("{}: {} doesn't match /{}/", name, value, re_expr))
    }
}

pub fn prompt_yn(prompt: &str) -> io::Result<bool> {
    let mut stderr = io::stderr();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut buff = String::with_capacity(5);

    // mixing stdout/stderr output is always a mess, but the only time we really
    // do it is with prompts. flush it here so our callers don't have to
    stdout.flush()?;
    stderr.flush()?;

    loop {
        stderr.write_all(prompt.as_bytes())?;
        stderr.flush()?;

        buff.clear();
        stdin.read_line(&mut buff)?;

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
    res == 0
}

pub fn pretty_date(timestamp: i64) -> String {
    let dt = Local.timestamp(timestamp, 0);
    let local = dt.with_timezone(&Local);
    local.to_rfc2822()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_constant_time_compare() {
        let compare = |actual: &str, expected: &str| {
            constant_time_compare(&actual.as_bytes(), &expected.as_bytes())
        };
        assert_eq!(true, compare("abc", "abc"));
        assert_eq!(false, compare("abc", "ab"));
        assert_eq!(false, compare("ab", "abc"));
        assert_eq!(false, compare("ab", "aba"));
        assert_eq!(false, compare("abd", "abc"));
    }
}
