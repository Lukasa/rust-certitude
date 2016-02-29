// Provides the abstraction layer: calls into the appropriate platform-native functions.
use ValidationResult;

#[cfg(target_os = "macos")]
use osx::validate_cert_chain as backend;
#[cfg(windows)]
use windows::validate_cert_chain as backend;

/// Validate a chain of certificates.
pub fn validate_cert_chain(encoded_certs: &[&[u8]], hostname: &str) -> ValidationResult {
    backend(encoded_certs, hostname)
}
