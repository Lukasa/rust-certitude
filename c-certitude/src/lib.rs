// Functions for validating certificates on many platforms, with a C abi.
#![deny(warnings)]

extern crate libc;
extern crate certitude;

use std::ffi::CStr;
use std::slice;
use libc::c_char;

pub use certitude::ValidationResult;


/// A C-ABI compatible version of the cert validation function. It does some work to transform the data,
/// and then just calls the cert validation function from certitude.
///
/// Here are the rules for calling this from C.
///
/// - encoded_certs is an array of pointers to DER-encoded representations of the certificates in the
///   certificate chain. Neither the pointer array nor the DER-encoded representations of the certs
///   are null-terminated.
/// - cert_sizes is an array of lengths for each DER-encoded cert. This array has the exact same length
///   as the array in encoded_certs. These lengths must not include any null-terminators that may be at
///   the end of the DER-encoded certs.
/// - cert_count is the number of elements in both the encoded_certs and cert_sizes array.
/// - hostname is the UTF-8 encoded hostname to validate the cert chain against. This string must be
///   null-terminated.
///
/// Rust takes ownership of none of these objects: where necessary it makes its own copies, but
/// generally speaking it expects all of the data passed to be it to remain valid for the duration
/// of the function call. The caller retains ownership, however, and is responsible for freeing all
/// the relevant data.
///
/// The C header for this function is:
///
/// ```c
/// extern uint32_t validate_cert_chain(uint8_t **encoded_certs,
///                                     size_t *cert_sizes,
///                                     size_t cert_count,
///                                     const char *hostname);
/// ```
#[no_mangle]
pub extern "C" fn validate_cert_chain(encoded_certs: *mut *const u8, cert_sizes: *mut usize, cert_count: usize, hostname: *const c_char) -> u32 {
    // First, turn the hostname into a CStr. CStr explicitly doesn't own the bytes, so we avoid
    // an extra copy here (and then awkwardly freeing the underlying string, which would be Not Good).
    let encoded_hostname = match unsafe { CStr::from_ptr(hostname).to_str() } {
        Ok(h) => h,
        Err(_) => return ValidationResult::MalformedHostname as u32,
    };

    // This works best if we turn the collection of encoded certs into a slice of u8 objects.
    // We can do this in place by being *very* careful.
    // First, convince Rust that we have a slice of pointers to u8.
    // Note that we *must not* use a vector here: vectors own their memory, and so using
    // a vector will cause Rust to do all kinds of crazy stuff.
    let temp_cert_slice = unsafe { slice::from_raw_parts(encoded_certs, cert_count) };
    let cert_sizes = unsafe { slice::from_raw_parts(cert_sizes, cert_count) };

    // Then, build a new slice transforming all the encoded certs into slices of u8.
    // Here we want the backing objects to be slices, but we're ok with their container
    // being a vector (the vector will dealloc the slices, but the slices borrow their
    // memory so the underlying memory should be totally safe).
    let cert_slice = temp_cert_slice.iter()
                                    .zip(cert_sizes)
                                    .map(|(&cert, &size)| unsafe { slice::from_raw_parts(cert, size) })
                                    .collect::<Vec<&[u8]>>();

    // We can now validate the items. We've taken ownership of nothing here.
    certitude::validate_cert_chain(&cert_slice, encoded_hostname) as u32
}