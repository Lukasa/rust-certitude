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
#[derive(PartialEq, Debug)]
pub enum ValidationResult {
    Trusted = 1,
    NotTrusted,
    MalformedCertificateInChain,
    MalformedHostname,
    UnableToBuildTrustStore,
    ErrorDuringValidation,
}


pub mod platform;
#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod osx;

#[cfg(test)]
mod test {
    use platform::validate_cert_chain;
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
