// Provides the abstraction layer: calls into the appropriate platform-native functions.
use ValidationResult;

#[cfg(target_os = "macos")]
use osx::validate_cert_chain as backend;
#[cfg(windows)]
use windows::validate_cert_chain as backend;

/// Validate a chain of certificates.
///
/// Given a chain of DER-encoded X.509 certificates and the hostname that you're
/// contacting, validates that the system considers that certificate chain valid for
/// the connection.
///
/// The `encoded_certs` should be in order of specificity: the "leaf" certificate first,
/// then each intermediate certificate in order. For the intermediate certificates, order
/// *may not* be important, but it is *extremely important* that the leaf come first.
/// If at all possible, preserve the order.
///
/// # Examples
///
/// Given a pre-allocated collection of certificates:
///
/// ```
/// match validate_cert_chain(certs, "google.com") {
///     ValidationResult::Trusted => Ok("success!"),
///     ValidationResult::NotTrusted => Ok("man in the middle!"),
///     _ => Err("an internal error occurred!"),
/// }
/// ```
pub fn validate_cert_chain(encoded_certs: &[&[u8]], hostname: &str) -> ValidationResult {
    backend(encoded_certs, hostname)
}

