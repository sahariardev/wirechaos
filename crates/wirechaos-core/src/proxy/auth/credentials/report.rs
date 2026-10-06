use std::fmt;

/// One validation failure.
///
/// It deliberately holds only the *shape* of the problem — the user name, the
/// field, and a fixed reason string. Secret values are never stored here, so a
/// report can be pasted into a ticket without leaking anything.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryError {
    user: Option<String>,
    field: &'static str,
    reason: &'static str,
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(user) => write!(f, "user {user}: {}: {}", self.field, self.reason),
            None => write!(f, "{}: {}", self.field, self.reason),
        }
    }
}

/// The aggregate of every validation failure in one credential source.
///
/// A store is never built from a partial parse: either every entry is valid or
/// the caller gets the full list of entries that are not.
#[derive(Debug, Clone)]
pub struct ConfigError {
    entries: Vec<EntryError>,
}

impl ConfigError {
    pub fn single(field: &'static str, reason: &'static str) -> Self {
        Self {
            entries: vec![EntryError {
                user: None,
                field,
                reason,
            }],
        }
    }

    /// The number of distinct validation failures collected.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no failure was recorded. A `ConfigError` value always contains at
    /// least one entry, so this exists mainly to satisfy the `len`/`is_empty`
    /// pairing clippy expects.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} credentials configuration error(s)",
            &self.entries.len()
        )?;

        for entry in &self.entries {
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
            Err(ConfigError {
                entries: self.entries,
            })
        }
    }
}
