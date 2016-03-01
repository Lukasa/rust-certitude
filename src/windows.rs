use std::mem;
use std::ptr;
use std::string::String;
use std::ffi::OsStr;
use std::os::raw::{c_void, c_char};
use std::os::windows::ffi::OsStrExt;

use crypt32::{CertOpenStore, CertCloseStore, CertAddEncodedCertificateToStore,
              CertFreeCertificateContext, CertGetCertificateChain,
              CertFreeCertificateChain, CertVerifyCertificateChainPolicy};
use winapi::minwindef::DWORD;
use winapi::wincrypt::{PCCERT_CHAIN_CONTEXT, CERT_STORE_PROV_MEMORY, HCERTSTORE,
                       CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, PCCERT_CONTEXT,
                       X509_ASN_ENCODING, CERT_STORE_ADD_ALWAYS, CERT_CHAIN_PARA,
                       CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
                       CERT_CHAIN_POLICY_SSL, szOID_PKIX_KP_SERVER_AUTH,
                       szOID_SERVER_GATED_CRYPTO, szOID_SGC_NETSCAPE};
use winapi::winnt::LPWSTR;

use ValidationResult;

pub fn validate_cert_chain(encoded_certs: &[&[u8]], hostname: &str) -> ValidationResult {
    let context = match build_cert_context(encoded_certs) {
        Ok(context) => context,
        Err(e) => return e,
    };
    let chain = match build_chain(context) {
        Ok(chain) => chain,
        Err(e) => return e,
    };
    verify_chain_against_policy(chain, hostname)
}


macro_rules! as_cchar_vec {
    ($e:expr) => {
        {
            let mut bytes = String::from($e).into_bytes();
            bytes.push(0);
            bytes.iter().map(|&b| b as c_char).collect()
        }
    }
}


// Sadly, winapi-rs doesn't yet have a structure we need, so I'll need to build it here.
#[repr(C)]
#[allow(non_snake_case)]
struct SSL_EXTRA_CERT_CHAIN_POLICY_PARA {
    cbSize: DWORD,
    dwAuthType: DWORD,
    fdwChecks: DWORD,
    pwszServerName: LPWSTR
}

impl Copy for SSL_EXTRA_CERT_CHAIN_POLICY_PARA {}
impl Clone for SSL_EXTRA_CERT_CHAIN_POLICY_PARA { fn clone(&self) -> SSL_EXTRA_CERT_CHAIN_POLICY_PARA {*self} }


// Private implementations. We need to do a lot of work here to make sure things
// behave properly. In particular, we need wrapper types.
struct CertStore(HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.0 as *mut _, 0);
        }
    }
}

struct CertContext(PCCERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.0 as *mut _);
        }
    }
}

struct CertChainContext(PCCERT_CHAIN_CONTEXT);

impl Drop for CertChainContext {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateChain(self.0 as *mut _);
        }
    }
}


// Verify that a given certificate chain meets the security policy.
fn verify_chain_against_policy(chain_context: CertChainContext, hostname: &str) -> ValidationResult {
    // To begin, we need to create the policy. The policy is simple: suitable for
    // SSL, suitable for this host. First, we need the hostname as a null-terminated array of wchar_t.
    // This bizarre one-liner does that.
    let mut encoded_host = OsStr::new(hostname).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>();

    // Then we need some structs to tell Windows what policy we want.
    let mut extra_policy = SSL_EXTRA_CERT_CHAIN_POLICY_PARA {
        cbSize: mem::size_of::<SSL_EXTRA_CERT_CHAIN_POLICY_PARA>() as u32,
        dwAuthType: 2,  // AUTHTYPE_SERVER
        fdwChecks: 0,
        pwszServerName: encoded_host.as_mut_ptr(),  // This is safe: the function won't modify the buffer.
    };
    let mut policy = CERT_CHAIN_POLICY_PARA {
        cbSize: mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        dwFlags: 0,
        pvExtraPolicyPara: &mut extra_policy as *mut _ as *mut c_void,
    };

    // Finally we need a structure where Windows can tell us the result.
    let mut result = CERT_CHAIN_POLICY_STATUS {
        cbSize: mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        dwError: 0,
        lChainIndex: 0,
        lElementIndex: 0,
        pvExtraPolicyStatus: ptr::null_mut(),
    };

    // We can now ask Windows to validate.
    unsafe {
        let verified = CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL as *const i8,
            chain_context.0,
            &mut policy,
            &mut result,
        );

        if verified == 0 {
            return ValidationResult::ErrorDuringValidation;
        }
    }
    // This is probably overbroad: look at the errors in https://msdn.microsoft.com/en-us/library/windows/desktop/aa377188(v=vs.85).aspx
    // and re-evaluate.
    match result.dwError {
        0 => ValidationResult::Trusted,
        _ => ValidationResult::NotTrusted,
    }
}


// Builds a certificate chain context. This tells Windows to build a chain, but
// doesn't validate that it's acceptable for the host in question.
fn build_chain(cert_context: CertContext) -> Result<CertChainContext, ValidationResult> {
    // Define acceptable certificate uses. In this case, we would like to just use SERVER_AUTH, but
    // Chrome uses SERVER_GATED_CRYPTO and SGC_NETSCAPE because...well, who knows, but let's do that
    // anyway.
    //
    // We get mutable pointers to these strings and then a mutable pointer to the array, but only
    // because Windows isn't good enough with saying that things are const. These won't change.
    // Annoyingly, though, we have to convince Rust to do it.
    let mut server_auth: Vec<c_char> = as_cchar_vec!(szOID_PKIX_KP_SERVER_AUTH);
    let mut server_gated_crypto: Vec<c_char> = as_cchar_vec!(szOID_SERVER_GATED_CRYPTO);
    let mut sgc_netscape: Vec<c_char> = as_cchar_vec!(szOID_SGC_NETSCAPE);
    let mut usage = [
        server_auth.as_mut_ptr(),
        server_gated_crypto.as_mut_ptr(),
        sgc_netscape.as_mut_ptr(),
    ];

    let mut chain_parameters: CERT_CHAIN_PARA = unsafe{ mem::zeroed() };
    chain_parameters.RequestedUsage.dwType = 1;  // USAGE_MATCH_TYPE_OR
    chain_parameters.RequestedUsage.Usage.cUsageIdentifier = usage.len() as u32;
    chain_parameters.RequestedUsage.Usage.rgpszUsageIdentifier = usage.as_mut_ptr();
    chain_parameters.cbSize = mem::size_of::<CERT_CHAIN_PARA>() as u32;

    let mut chain_context_ptr = ptr::null();
    unsafe {
        let got_chain = CertGetCertificateChain(
            ptr::null_mut(),  // default engine
            cert_context.0,  // leaf certificate
            ptr::null_mut(),  // use the default system time
            (*(cert_context.0)).hCertStore,  // where to find intermediate certs
            &mut chain_parameters,  // The chain building constraints
            0,  // no flags
            ptr::null_mut(),  // reserved
            &mut chain_context_ptr
        );
        if got_chain == 0 {
            return Err(ValidationResult::NotTrusted);
        }
        if chain_context_ptr.is_null() {
            return Err(ValidationResult::ErrorDuringValidation);
        }
    }
    let context = CertChainContext(chain_context_ptr as PCCERT_CHAIN_CONTEXT);
    Ok(context)
}


// Builds the certificate chain provided into a certificate store.
fn build_cert_context(encoded_certs: &[&[u8]]) -> Result<CertContext, ValidationResult> {
    // Build a backing store, in-memory.
    let store_ptr = unsafe {
        let backing_store = CertOpenStore(
            CERT_STORE_PROV_MEMORY as *const i8,
            0,
            0,
            CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
            ptr::null(),
        );
        if backing_store.is_null() {
            return Err(ValidationResult::ErrorDuringValidation);
        }
        backing_store
    };
    let store = CertStore(store_ptr);
    let mut primary_cert_ptr = ptr::null();

    // Then, add the leaf cert. We want to hold on to a reference to it, because
    // that's what we'll end up returning.
    unsafe {
        let ok = CertAddEncodedCertificateToStore(
            store.0,
            X509_ASN_ENCODING,
            encoded_certs[0].as_ptr(),
            encoded_certs[0].len() as u32,
            CERT_STORE_ADD_ALWAYS,
            &mut primary_cert_ptr,
        );
        if ok == 0 {
            return Err(ValidationResult::MalformedCertificateInChain);
        }
    }
    let primary_cert = CertContext(primary_cert_ptr);

    // Now, for every other cert, add it to the store. Don't bother
    // keeping a reference.
    for cert in &encoded_certs[1..] {
        unsafe {
            let ok = CertAddEncodedCertificateToStore(
                store.0,
                X509_ASN_ENCODING,
                cert.as_ptr(),
                cert.len() as u32,
                CERT_STORE_ADD_ALWAYS,
                ptr::null_mut(),
            );
            if ok == 0 {
                return Err(ValidationResult::MalformedCertificateInChain);
            }
        }
    }

    Ok(primary_cert)
}

#[cfg(test)]
mod test {
    use windows::validate_cert_chain;
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
        assert_eq!(valid, ValidationResult::MalformedCertificateInChain);
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