use crate::proxy::replication_mode::ReplicationMode;
use crate::proxy::replication_mode::ReplicationMode::{ReplicationLogical, ReplicationOff};
use std::collections::HashMap;
use tokio::io;

pub fn parse_options(
    options: String,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let tokens = split_option_tokens(options);
    let mut result: HashMap<String, String> = HashMap::new();
    let mut i = 0;

    while i < tokens.len() {
        let token = tokens.get(i).unwrap().as_str();

        match token {
            //"-c key=value"
            "-c" => {
                i += 1;
                let value_token = tokens.get(i).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("missing value after -c: {}", i),
                    )
                })?;

                let (key, value) = split_key_value(value_token)?;

                result.insert(key.to_string(), value.to_string());
            }

            //-ckey=value
            t if t.starts_with("-c") => {
                let (key, value) = split_key_value(&t[2..])?;

                result.insert(key.to_string(), value.to_string());
            }

            t if t.starts_with("--") => {
                let (key, value) = split_key_value(&t[2..])?;

                let key = key.replace("-", "_");

                result.insert(key, value.to_string());
            }
            _ => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported option",
                )))
            }
        }

        i += 1;
    }

    Ok(result)
}

fn split_key_value(token: &str) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    let (key, value) = token
        .split_once('=')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid key/value size"))?;

    if key.is_empty() || value.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid key/value size",
        )));
    }

    Ok((key, value))
}
pub fn split_option_tokens(s: String) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut curr = String::new();
    let mut escaped = false;

    for c in s.chars() {
        if escaped {
            escaped = false;
            curr.push(c);
            continue;
        }

        if c == '\\' {
            escaped = true;
            continue;
        }

        if c == ' ' || c == '\t' {
            if !curr.is_empty() {
                tokens.push(curr);
                curr = String::new();
            }
            continue;
        }

        curr.push(c);
    }

    if !curr.is_empty() {
        tokens.push(curr);
    }

    tokens
}

pub fn parse_replication_mode(
    value: String,
) -> Result<ReplicationMode, Box<dyn std::error::Error>> {
    match value.to_lowercase().as_str() {
        "" | "false" | "off" | "no" | "0" | "f" | "n" => Ok(ReplicationOff),
        "true" | "on" | "yes" | "1" | "t" | "y" => Ok(ReplicationMode::ReplicationPhysical),
        "database" => Ok(ReplicationLogical),
        _ => {
            Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid value",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- split_option_tokens ----

    #[test]
    fn split_empty_input_yields_no_tokens() {
        assert!(split_option_tokens(String::new()).is_empty());
    }

    #[test]
    fn split_single_token() {
        assert_eq!(
            split_option_tokens("application_name=psql".to_string()),
            ["application_name=psql"]
        );
    }

    #[test]
    fn split_on_single_space() {
        // The separator is consumed, never carried into a token.
        assert_eq!(split_option_tokens("a b c".to_string()), ["a", "b", "c"]);
    }

    #[test]
    fn split_on_tab() {
        assert_eq!(split_option_tokens("a\tb".to_string()), ["a", "b"]);
    }

    #[test]
    fn split_on_tab_for_diff_token() {
        assert_eq!(
            split_option_tokens("-ck=value\t--k2=valu2".to_string()),
            ["-ck=value", "--k2=valu2"]
        );
    }

    #[test]
    fn split_escaped_space_stays_in_token() {
        assert_eq!(split_option_tokens("a\\ b".to_string()), ["a b"]);
    }

    #[test]
    fn split_escaped_backslash_is_literal() {
        assert_eq!(split_option_tokens("a\\\\b".to_string()), ["a\\b"]);
    }

    #[test]
    fn split_consecutive_spaces_collapse_into_one_separator() {
        // Runs of whitespace are separators, not tokens: no empty or
        // whitespace-only token is produced.
        assert_eq!(split_option_tokens("a  b".to_string()), ["a", "b"]);
    }

    // ---- parse_options ----

    #[test]
    fn parse_empty_input_yields_empty_map() {
        let map = parse_options(String::new()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_joined_dash_c_option() {
        // -ckey=value
        let map = parse_options("-ck=value".to_string()).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("k").map(String::as_str), Some("value"));
    }

    #[test]
    fn parse_multi_option() {
        let map = parse_options("-ck=value\t--k2=value2".to_string()).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("k").map(String::as_str), Some("value"));
        assert_eq!(map.get("k2").map(String::as_str), Some("value2"));
    }

    #[test]
    fn parse_dash_c_with_separate_value() {
        // "-c key=value": the `-c` arm consumes the following token.
        let map = parse_options("-c k=value".to_string()).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("k").map(String::as_str), Some("value"));
    }

    #[test]
    fn parse_double_dash_option_normalizes_underscore() {
        let map = parse_options("--connection-limit=5".to_string()).unwrap();
        assert_eq!(map.get("connection_limit").map(String::as_str), Some("5"));
    }

    #[test]
    fn parse_multiple_space_separated_options() {
        // Whitespace separates options, so every one of them is parsed.
        let map = parse_options("-ck=v --foo=bar".to_string()).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("k").map(String::as_str), Some("v"));
        assert_eq!(map.get("foo").map(String::as_str), Some("bar"));
    }

    #[test]
    fn parse_rejects_joined_dash_c_without_equals() {
        // A missing '=' must be an error, not a panic on the client's input.
        let err = parse_options("-ck".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "invalid key/value size");
    }

    #[test]
    fn parse_rejects_double_dash_without_equals() {
        let err = parse_options("--connection-limit".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "invalid key/value size");
    }

    #[test]
    fn parse_value_may_contain_equals() {
        // Only the first '=' separates the key from the value.
        let map = parse_options("--application-name=a=b".to_string()).unwrap();
        assert_eq!(map.get("application_name").map(String::as_str), Some("a=b"));
    }

    #[test]
    fn parse_rejects_missing_value_after_dash_c() {
        let err = parse_options("-c".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "missing value after -c: 1");
    }

    #[test]
    fn parse_rejects_empty_value() {
        let err = parse_options("-ck=".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "invalid key/value size");
    }

    #[test]
    fn parse_rejects_empty_key() {
        let err = parse_options("-c=v".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "invalid key/value size");
    }

    #[test]
    fn parse_rejects_double_dash_with_empty_value() {
        let err = parse_options("--foo=".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "invalid key/value size");
    }

    #[test]
    fn parse_rejects_unsupported_option() {
        let err = parse_options("garbage".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported option");
    }
}
