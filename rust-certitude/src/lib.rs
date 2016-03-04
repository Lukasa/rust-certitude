#![deny(warnings)]
//! Functions for validating certificates on many platforms.
//!
//! Certitude focuses on making it possible to validate a chain of X.509 certificates used
//! for a TLS connection by using the appropriate platform-specific logic, rather than by
//! relying on the TLS library that actually makes the connection. This approach is useful
//! for libraries that want to use OpenSSL build TLS connections on Windows and OS X, but
//! that want to exhibit "platform-native" behaviour on those systems.
//!
//! Currently Certitude *only* supports Windows and OS X: it explicitly does not support
//! Linux or any other Unix, where it is expected that the verification logic provided by
//! OpenSSL (or the appropriate TLS library) used on those systems will be used instead.
//! As that library is likely the one responsible for actually handling the TLS logic, it
//! is likely pretty easy to use the built-in validation logic.

extern crate libc;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate security_framework;
#[cfg(windows)]
extern crate crypt32;
#[cfg(windows)]
extern crate winapi;



// TODO: Widen "NotTrusted".

/// Possible results from attempting to validate a certificate chain.
///
/// When attempting to validate a certificate chain, in addition to the two "successful"
/// results (`ValidationResult::Trusted` and `ValidationResult::NotTrusted`), there are
/// numerous possible error conditions. This enum allows for expressing those error
/// conditions.
///
/// Note that due to the vagaries of the system libraries, it is possible that a
/// misleading error may be generated: for example, the hostname may be malformed
/// but in a manner that does not immediate generate a `ValidationResult::MalformedHostname`
/// result. That's unfortunate, but there is relatively little that can be done about that
/// in the absence of clearer system APIs.
#[derive(PartialEq, Debug)]
pub enum ValidationResult {
    Trusted = 1,
    NotTrusted,
    MalformedCertificateInChain,
    UnableToBuildTrustStore,
    ErrorDuringValidation,
    MissingFunctionality,
    UserAuthenticationRequired,
    MalformedHostname,
}

pub use self::platform::validate_cert_chain;

mod platform;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "macos")]
mod osx;

#[cfg(test)]
mod test {
    use validate_cert_chain;
    use ValidationResult;

    pub fn certifi_chain() -> Vec<&'static[u8]> {
        let leaf = include_bytes!("../fixtures/certifi/leaf.crt");
        let first_inter = include_bytes!("../fixtures/certifi/first-intermediate.crt");
        let second_inter = include_bytes!("../fixtures/certifi/second-intermediate.crt");

        vec![leaf, first_inter, second_inter]
    }

    pub fn expired_chain() -> Vec<&'static[u8]> {
        let leaf = include_bytes!("../fixtures/expired/leaf.crt");
        let first_inter = include_bytes!("../fixtures/expired/first-intermediate.crt");
        let second_inter = include_bytes!("../fixtures/expired/second-intermediate.crt");

        vec![leaf, first_inter, second_inter]
    }

    pub fn self_signed_chain() -> Vec<&'static[u8]> {
        let leaf = include_bytes!("../fixtures/self-signed/leaf.crt");

        vec![leaf]
    }

    #[test]
    fn can_validate_good_chain() {
        let chain = certifi_chain();
        let valid = validate_cert_chain(&chain, "certifi.io");
        assert_eq!(valid, ValidationResult::Trusted);
    }

    #[test]
    fn fails_on_bad_hostname() {
        let chain = certifi_chain();
        let valid = validate_cert_chain(&chain, "lukasa.co.uk");
        assert_eq!(valid, ValidationResult::NotTrusted);
    }

    #[test]
    fn fails_on_bad_cert() {
        let mut good_chain = certifi_chain();
        let originals = good_chain.split_first_mut().unwrap();
        let leaf = originals.0;
        let intermediates = originals.1;

        // Deliberately truncate the leaf cert.
        let mut certs = vec![&leaf[1..50]];
        certs.extend(intermediates.iter());
        let valid = validate_cert_chain(&certs, "certifi.io");
        if cfg!(target_os = "macos") {
            assert_eq!(valid, ValidationResult::NotTrusted);
        } else {
            // Windows
            assert_eq!(valid, ValidationResult::MalformedCertificateInChain);
        }
    }

    #[test]
    fn fails_on_expired_cert() {
        let chain = expired_chain();
        let valid = validate_cert_chain(&chain, "expired.badssl.com");
        assert_eq!(valid, ValidationResult::NotTrusted);
    }

    #[test]
    fn test_fails_on_self_signed() {
        let chain = self_signed_chain();
        let valid = validate_cert_chain(&chain, "self-signed.badssl.com");
        assert_eq!(valid, ValidationResult::NotTrusted);
    }
}
