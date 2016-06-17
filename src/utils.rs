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
        return Err(format!("{:?} doesn't match {:?}",
                           value, re_expr))
    }
}
