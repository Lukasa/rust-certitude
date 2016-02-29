use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::secure_transport::ProtocolSide;
use security_framework::trust::{SecTrust, TrustResult};

use ValidationResult;

pub fn validate_cert_chain(encoded_certs: &[&[u8]], hostname: &str) -> ValidationResult {
    let mut certs = Vec::new();
    for encoded_cert in encoded_certs {
        let cert = SecCertificate::from_der(encoded_cert);
        match cert {
            Ok(cert) => certs.push(cert),
            // This is remarkably difficult to hit: OS X mostly parses the cert
            // lazily. Still possible though.
            Err(_) => return ValidationResult::MalformedCertificateInChain,
        };
    }

    let ssl_policy = match SecPolicy::for_ssl(ProtocolSide::Client, hostname) {
        Ok(policy) => policy,
        Err(_) => return ValidationResult::MalformedHostname,
    };
    let trust = match SecTrust::create_with_certificates(&certs[..], &[ssl_policy]) {
        Ok(trust) => trust,
        Err(_) => return ValidationResult::UnableToBuildTrustStore,
    };

    // Errors here are really unexpected.
    match trust.evaluate() {
        Ok(result) => trust_result_to_validation_result(result),
        Err(_) => ValidationResult::ErrorDuringValidation,
    }
}


// Convert a TrustResult to a ValidationResult.
fn trust_result_to_validation_result(trust_result: TrustResult) -> ValidationResult {
    match trust_result {
        TrustResult::Invalid | TrustResult::Unspecified => ValidationResult::Trusted,
        _ => ValidationResult::NotTrusted,
    }
}


#[cfg(test)]
mod test {
    use osx::validate_cert_chain;
    use test::{expired_chain, certifi_chain, self_signed_chain};
    use ValidationResult;

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
        assert_eq!(valid, ValidationResult::NotTrusted);
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
