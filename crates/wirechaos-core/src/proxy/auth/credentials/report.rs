use std::fmt::{self};

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryError {
    user: Option<String>,
    field: &'static str,
    reason: &'static str,
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(user) => write!(f, "user {user} : {} : {}", self.field, self.reason),
            _ => write!(f, "field:{} reason: {}", self.field, self.reason),
        }
    }
}

#[derive(Debug)]
pub struct ConfigError {
    etries: Vec<EntryError>,
}

impl ConfigError {
    pub fn single(field: &'static str, reason: &'static str) -> Self {
        Self {
            etries: vec![EntryError {
                user: None,
                field,
                reason,
            }],
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} credentials configuration errors", &self.etries.len())?;

        for entry in &self.etries {
            write!(f, "\n - {entry}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ConfigError {}

#[derive(Default)]
pub(crate) struct ErrorBag {
    entries: Vec<EntryError>,
}

impl ErrorBag {
    pub(crate) fn push(&mut self, user: Option<&str>, field: &'static str, reason: &'static str) {
        self.entries.push(EntryError {
            user: user.map(str::to_owned),
            field,
            reason,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn into_result(self) -> Result<(), ConfigError> {
        if self.is_empty() {
            Ok(())
        } else {
            return Err(ConfigError {
                etries: self.entries,
            });
        }
    }
}
