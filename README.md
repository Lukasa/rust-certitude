# Certitude for Rust

This repository contains a proof-of-concept for building a cross-platform Rust library that is capable of using the system-native X.509 stack to validate certificates.

This is inspired by the Chrome web browser's choice to use BoringSSL (a fork of OpenSSL) to do their TLS at the protocol level, but to use the system's logic for validating certificates. This allows the Chrome application to feel "native" when it comes to certificate management, without requiring their network engineers to understand the idiosyncracies of each platform-native TLS implementation.

## API

The goal with this library is provide two APIs: one that is suited to Rust directly, and then one that is available using the C ABI that can be called by as many programming languages as possible. This will make it possible to reduce the duplication of work across languages: each language need only make a single FFI call to the Rust library, which will then handle the abstraction to the various platforms.

The Rust API currently looks like this:

```rust
extern crate certitude;

use certitude::os_x::validate_cert_chain;

fn example() {
    // Assume certs is a Vector of DER-encoded certificates.
    let valid = validate_cert_chain(certs, "example.com");

    if valid {
        // The certificate chain is valid.
    } else {
        // The certificate chain is invalid in some way.
    }
}
```

In the future, the OS X and Windows implementations should be transparently switched in and out, such that a user of this library can transparently use a single API and have the appropriate platform-specific logic used directly, without their intervention.

## Work In Progress

This is currently a very early beta, and I'm mostly investigating the feasibility of the approach. Currently the library supports OS X and Windows as a valid certificate verification platform. I will investigate the feasibility of hooking into OpenSSL, though that's considered a strictly less important problem than sorting this out on Windows and OS X, as people using OpenSSL for their TLS will already have access to OpenSSL's native validation logic.
