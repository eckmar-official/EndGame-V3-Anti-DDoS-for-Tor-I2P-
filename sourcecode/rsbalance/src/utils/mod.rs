pub fn strip_prefix(s: &str, prefix: &str) -> String {
    s.strip_prefix(prefix).unwrap_or(s).to_owned()
}

pub fn strip_suffix(s: &str, suffix: &str) -> String {
    s.strip_suffix(suffix).unwrap_or(s).to_owned()
}

pub fn fmt_first(is_first_desc: bool) -> String {
    if is_first_desc { "first" } else { "second" }.to_owned()
}