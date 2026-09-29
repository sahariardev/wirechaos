//! TLS certificate hashing for `tls-server-end-point` channel binding
//! (RFC 5929 §4.1), plus the per-connection frontend TLS bundle.
//!
//! Only the leaf certificate matters, hashed exactly as it appears octet for
//! octet in the TLS `Certificate` message. The digest is derived once, when the
//! certificate is loaded, and then reused for every session that presents it.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

/// The hash function RFC 5929 §4.1 selects for a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertHash {
    pub algorithm: HashAlgorithm,
    /// Raw digest bytes (32/48/64 long), never base64 or hex.
    pub digest: Vec<u8>,
}

/// The frontend TLS material a connection carries: what to present to the
/// client, and what that client is expected to bind its proof to.
#[derive(Clone)]
pub struct FrontendTls {
    pub acceptor: TlsAcceptor,
    /// `None` when the certificate's `tls-server-end-point` hash is undefined;
    /// `-PLUS` must then not be advertised.
    pub cert_hash: Option<CertHash>,
}

/// A certificate that could not be turned into a channel-binding hash at all.
///
/// A merely *undefined* hash is not an error: that is `Ok(None)`.
#[derive(Debug, Error)]
pub enum CertHashError {
    #[error("certificate DER is malformed")]
    Malformed,
}

/// The GS2 header for `tls-server-end-point` channel binding.
pub const TLS_SERVER_END_POINT_HEADER: &[u8] = b"p=tls-server-end-point,,";

impl CertHash {
    /// Compute the RFC 5929 `tls-server-end-point` hash of a leaf certificate.
    ///
    /// `Ok(None)` means the certificate's signature algorithm has no single
    /// applicable hash (Ed25519/Ed448, RSASSA-PSS, or an algorithm not modelled
    /// here), so `-PLUS` must not be offered. `Err` means the DER itself could
    /// not be parsed — a startup-time configuration error.
    pub fn new(der: &[u8]) -> Result<Option<CertHash>, CertHashError> {
        let (_, certificate) =
            X509Certificate::from_der(der).map_err(|_| CertHashError::Malformed)?;

        let Some(algorithm) =
            hash_algorithm_for_oid_str(&certificate.signature_algorithm.algorithm.to_id_string())
        else {
            return Ok(None);
        };

        // RFC 5929 hashes the certificate as it appears in the Certificate
        // message, i.e. these exact DER bytes — not the signature value.
        let digest = match algorithm {
            HashAlgorithm::Sha256 => Sha256::digest(der).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(der).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(der).to_vec(),
        };

        Ok(Some(CertHash { algorithm, digest }))
    }

    /// `cbind-input` = GS2 header ‖ raw certificate hash. Raw bytes, unencoded.
    pub fn cbind_input(&self) -> Vec<u8> {
        let mut input = Vec::with_capacity(TLS_SERVER_END_POINT_HEADER.len() + self.digest.len());
        input.extend_from_slice(TLS_SERVER_END_POINT_HEADER);
        input.extend_from_slice(&self.digest);
        input
    }

    /// The value the client must send in its `c=` attribute.
    pub fn expected_c(&self) -> String {
        B64.encode(self.cbind_input())
    }
}

/// Apply the RFC 5929 §4.1 hash-selection rule to a signature-algorithm OID.
///
/// `None` means the channel binding is *undefined* for this certificate. The
/// caller must then not offer `-PLUS`; a guessed hash would be indistinguishable
/// from a man-in-the-middle to the client.
fn hash_algorithm_for_oid_str(oid: &str) -> Option<HashAlgorithm> {
    match oid {
        // MD5 and SHA-1 signatures are upgraded to SHA-256.
        "1.2.840.113549.1.1.4"     // md5WithRSAEncryption
        | "1.2.840.113549.1.1.5"   // sha1WithRSAEncryption
        | "1.2.840.10045.4.1"      // ecdsa-with-SHA1
        | "1.2.840.10040.4.3"      // dsa-with-SHA1
        // SHA-256 signatures.
        | "1.2.840.113549.1.1.11"  // sha256WithRSAEncryption
        | "1.2.840.10045.4.3.2"    // ecdsa-with-SHA256
        | "2.16.840.1.101.3.4.3.2" // dsa-with-SHA256
        => Some(HashAlgorithm::Sha256),

        "1.2.840.113549.1.1.12"  // sha384WithRSAEncryption
        | "1.2.840.10045.4.3.3"  // ecdsa-with-SHA384
        => Some(HashAlgorithm::Sha384),

        "1.2.840.113549.1.1.13"  // sha512WithRSAEncryption
        | "1.2.840.10045.4.3.4"  // ecdsa-with-SHA512
        => Some(HashAlgorithm::Sha512),

        // Ed25519/Ed448 sign without a hash, RSASSA-PSS carries it in its
        // parameters, and anything else is unknown: all leave the binding
        // undefined rather than binding to a guess.
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Generate a self-signed certificate whose `signatureAlgorithm` is the one
    /// tied to `algorithm`, and return its DER.
    fn generated_cert(algorithm: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate_for(algorithm).expect("generate key pair");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("certificate params");
        let certificate = params
            .self_signed(&key_pair)
            .expect("sign self-signed certificate");
        certificate.der().as_ref().to_vec()
    }

    #[test]
    fn hash_algorithm_follows_rfc5929() {
        // A certificate signed with exactly one hash uses that hash.
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.113549.1.1.11"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.10045.4.3.2"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.113549.1.1.12"),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.10045.4.3.3"),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.113549.1.1.13"),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.10045.4.3.4"),
            Some(HashAlgorithm::Sha512)
        );

        // MD5 and SHA-1 signed certificates are upgraded to SHA-256.
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.113549.1.1.4"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.113549.1.1.5"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            hash_algorithm_for_oid_str("1.2.840.10045.4.1"),
            Some(HashAlgorithm::Sha256)
        );

        // No single hash (Ed25519/Ed448), parameters-only (RSASSA-PSS), and
        // unknown algorithms are undefined, so `-PLUS` must not be offered.
        assert_eq!(hash_algorithm_for_oid_str("1.3.101.112"), None);
        assert_eq!(hash_algorithm_for_oid_str("1.3.101.113"), None);
        assert_eq!(hash_algorithm_for_oid_str("1.2.840.113549.1.1.10"), None);
        assert_eq!(hash_algorithm_for_oid_str("1.2.3.4"), None);
    }

    #[test]
    fn digest_is_the_hash_of_the_whole_certificate() {
        let der = generated_cert(&rcgen::PKCS_ECDSA_P256_SHA256);
        let cert_hash = CertHash::new(&der)
            .expect("certificate must parse")
            .expect("ECDSA-SHA256 has a defined hash");

        assert_eq!(cert_hash.algorithm, HashAlgorithm::Sha256);
        assert_eq!(cert_hash.digest, Sha256::digest(&der).to_vec());
        assert_eq!(cert_hash.digest.len(), 32);
    }

    #[test]
    fn sha384_certificate_uses_sha384() {
        let der = generated_cert(&rcgen::PKCS_ECDSA_P384_SHA384);
        let cert_hash = CertHash::new(&der)
            .expect("certificate must parse")
            .expect("ECDSA-SHA384 has a defined hash");

        assert_eq!(cert_hash.algorithm, HashAlgorithm::Sha384);
        assert_eq!(cert_hash.digest, Sha384::digest(&der).to_vec());
        assert_eq!(cert_hash.digest.len(), 48);
    }

    #[test]
    fn ed25519_certificate_is_undefined_not_guessed() {
        let der = generated_cert(&rcgen::PKCS_ED25519);
        assert_eq!(
            CertHash::new(&der).expect("certificate must parse"),
            None,
            "Ed25519 has no hash, so tls-server-end-point is undefined"
        );
    }

    #[test]
    fn malformed_der_is_rejected() {
        assert!(CertHash::new(&[]).is_err());
        assert!(CertHash::new(b"not a certificate").is_err());
    }

    #[test]
    fn cbind_input_is_header_then_raw_digest() {
        let digest: Vec<u8> = (0..32).collect();
        let cert_hash = CertHash {
            algorithm: HashAlgorithm::Sha256,
            digest: digest.clone(),
        };

        let mut expected = TLS_SERVER_END_POINT_HEADER.to_vec();
        expected.extend_from_slice(&digest);

        assert_eq!(cert_hash.cbind_input(), expected);
        assert_eq!(cert_hash.expected_c(), B64.encode(expected));
    }
}
