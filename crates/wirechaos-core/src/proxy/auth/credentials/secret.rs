use std::borrow::Cow;

use crate::proxy::auth::verifier::Verifier;

/// Prepare a password for SCRAM key derivation (RFC 4013).
///
/// Returns the prepared form when SASLprep succeeds and borrows the original
/// when it does not. It never fails: a password PostgreSQL would accept must
/// not be rejected by the proxy merely because it contains a prohibited code
/// point.
pub fn prepare_password(password: &str) -> Cow<'_, str> {
    match stringprep::saslprep(password) {
        Ok(prepared) => prepared,
        Err(_) => Cow::Borrowed(password),
    }
}

/// Derive a verifier from a plaintext password, applying SASLprep first.
pub fn derive_verifier(password: &str, salt: &[u8], iterations: u32) -> Verifier {
    let prepared = prepare_password(password);
    Verifier::from_password(prepared.as_bytes(), salt, iterations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4013_examples() {
        // The RFC's table lists an *error* for the last two rows; PostgreSQL (and
        // therefore this crate) falls back to the raw bytes instead of failing.
        let cases: [(&str, &str); 7] = [
            ("I\u{00AD}X", "IX"),                     // SOFT HYPHEN mapped to nothing
            ("user", "user"),                         // no transformation
            ("USER", "USER"),                         // case preserved
            ("\u{00AA}", "a"),                        // NFKC
            ("\u{2168}", "IX"),                       // NFKC, matches row 1
            ("\u{0007}", "\u{0007}"),                 // prohibited: raw fallback
            ("\u{0627}\u{0031}", "\u{0627}\u{0031}"), // bidi: raw fallback
        ];

        for (input, expected) in cases {
            assert_eq!(
                prepare_password(input).as_ref(),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn derives_the_same_verifier_for_prepared_equivalents() {
        let salt = [7u8; 16];
        assert_eq!(
            derive_verifier("I\u{00AD}X", &salt, 4096).stored_key(),
            derive_verifier("\u{2168}", &salt, 4096).stored_key()
        );
    }

    #[test]
    fn falls_back_to_raw_bytes_when_preparation_fails() {
        let salt = [7u8; 16];
        assert_eq!(
            derive_verifier("\u{0007}", &salt, 4096).stored_key(),
            Verifier::from_password("\u{0007}".as_bytes(), salt, 4096).stored_key()
        );
    }
}
