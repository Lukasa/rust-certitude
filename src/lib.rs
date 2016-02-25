extern crate libc;
extern crate core_foundation;
extern crate security_framework;

macro_rules! fail_on_error {
    ($e:expr) => {
        match $e {
            Ok(s) => s,
            Err(_) => return false,
        }
    }
}

pub mod os_x {
    use security_framework::certificate::SecCertificate;
    use security_framework::policy::SecPolicy;
    use security_framework::secure_transport::ProtocolSide;
    use security_framework::trust::SecTrust;

    pub fn validate_cert_chain(encoded_certs: Vec<&[u8]>, hostname: &str) -> bool {
        let mut certs = Vec::new();
        for encoded_cert in encoded_certs {
            let cert = SecCertificate::from_der(encoded_cert);
            match cert {
                Ok(cert) => certs.push(cert),
                Err(_) => return false,
            }
        }

        let ssl_policy = fail_on_error!(SecPolicy::for_ssl(ProtocolSide::Client, hostname));
        let trust = fail_on_error!(SecTrust::create_with_certificates(&certs[..], &[ssl_policy]));

        // Deliberately swallow errors here: any error is likely to do with the
        // hostname or cert chain, and if those are invalid then by definition the
        // cert does not validate.
        match trust.evaluate() {
            Ok(result) => result.success(),
            Err(_) => false
        }
    }
}

#[cfg(test)]
mod test {
    use os_x::validate_cert_chain;

    fn certifi_chain() -> Vec<&'static[u8]> {
        let leaf = include_bytes!("../fixtures/certifi-leaf.crt");
        let first_inter = include_bytes!("../fixtures/certifi-first-intermediate.crt");
        let second_inter = include_bytes!("../fixtures/certifi-second-intermediate.crt");

        vec![leaf, first_inter, second_inter]
    }

    #[test]
    fn can_validate_good_chain() {
        let chain = certifi_chain();
        let valid = validate_cert_chain(chain, "certifi.io");
        assert_eq!(valid, true);
    }

    #[test]
    fn fails_on_bad_hostname() {
        let chain = certifi_chain();
        let valid = validate_cert_chain(chain, "lukasa.co.uk");
        assert_eq!(valid, false);
    }
}
