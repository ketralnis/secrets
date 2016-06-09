use regex;

pub fn validate_host(host_str: String) -> Result<(), String> {
    let re = regex::Regex::new(r"[a-zA-Z0-9.-]+(:[0-9]{1,5})?").unwrap();
    if re.is_match(&host_str) {
        return Ok(())
    } else {
        return Err("not a valid host".to_string())
    }
}
