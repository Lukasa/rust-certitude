extern crate libc;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate security_framework;
#[cfg(windows)]
extern crate crypt32;
#[cfg(windows)]
extern crate winapi;

macro_rules! fail_on_error {
    ($e:expr) => {
        match $e {
            Ok(s) => s,
            Err(_) => return false,
        }
    }
}

#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod osx;

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

    #[test]
    fn fails_on_bad_cert() {
        let mut good_chain = certifi_chain();
        let originals = good_chain.split_first_mut().unwrap();
        let leaf = originals.0;
        let intermediates = originals.1;

        // Deliberately truncate the leaf cert.
        let mut certs = vec![&leaf[1..50]];
        certs.extend(intermediates.iter());
        let valid = validate_cert_chain(certs, "certifi.io");
        assert_eq!(valid, false);
    }
}
