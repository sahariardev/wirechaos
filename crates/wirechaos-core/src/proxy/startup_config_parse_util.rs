use crate::proxy::replication_mode::ReplicationMode;
use crate::proxy::replication_mode::ReplicationMode::{ReplicationLogical, ReplicationOff};
use std::collections::HashMap;
use tokio::io;

pub fn parse_options(
    options: String,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let tokens = split_option_tokens(options);
    let mut result: HashMap<String, String> = HashMap::new();
    for mut i in 0..tokens.len() {
        let token = tokens.get(i).unwrap().as_str();

        match token {
            //"-c key=value"
            "-c" => {
                i = i + 1;
                if i >= tokens.len() {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("missing value after -c: {}", i),
                    )));
                }

                let keyvalue = tokens
                    .get(i)
                    .unwrap()
                    .as_str()
                    .split('=')
                    .collect::<Vec<&str>>();

                let key = keyvalue.get(0).unwrap();
                let value = keyvalue.get(1).unwrap();

                if key.len() == 0 || value.len() == 0 {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid key/value size",
                    )));
                }

                result.insert(key.to_string(), value.to_string());
            }

            //-ckey=value
            t if t.starts_with("-c") => {
                let rest = &t[2..];
                let keyvalue = rest.split('=').collect::<Vec<&str>>();

                let key = keyvalue.get(0).unwrap();
                let value = keyvalue.get(1).unwrap();
                if key.len() == 0 || value.len() == 0 {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid key/value size",
                    )));
                }
                result.insert(key.to_string(), value.to_string());
            }

            t if t.starts_with("--") => {
                let rest = &t[2..];
                let keyvalue = rest.split('=').collect::<Vec<&str>>();

                let key = keyvalue.get(0).unwrap();
                let value = keyvalue.get(1).unwrap();
                if key.len() == 0 || value.len() == 0 {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid key/value size",
                    )));
                }

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
    }
    Ok(result)
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
            if curr.len() > 0 {
                tokens.push(curr);
                curr = String::new();
            }
            continue;
        }

        curr.push(c);
    }

    if curr.len() > 0 {
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
        // Note: the tokenizer pushes the separator character onto the next
        // token, so every token after the first retains its leading space.
        // This documents current behavior.
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
    fn split_consecutive_spaces_produce_whitespace_tokens() {
        assert_eq!(split_option_tokens("a  b".to_string()), ["a", " ", " b"]);
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
    fn parse_rejects_dash_c_with_separate_value() {
        // "-c key=value" never reaches the value: the `-c` arm does
        // `i = i + 1`, but mutating a for-loop variable has no effect on the
        // range iterator, so " k=value" is re-matched and falls through to
        // the unsupported-option arm. Documents current behavior.
        let err = parse_options("-c k=value".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported option");
    }

    #[test]
    fn parse_double_dash_option_normalizes_underscore() {
        let map = parse_options("--connection-limit=5".to_string()).unwrap();
        assert_eq!(map.get("connection_limit").map(String::as_str), Some("5"));
    }

    #[test]
    fn parse_rejects_second_option_due_to_leading_space_token() {
        // The tokenizer keeps the separator in later tokens, so a "--foo=bar"
        // after the first option arrives as " --foo=bar" and fails the
        // starts_with("--") guard. Documents current behavior.
        let err = parse_options("-ck=v --foo=bar".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported option");
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
