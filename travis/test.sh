#!/bin/bash

set -e
set -x

# For the main lib, we build and test normally.
cd rust-certitude
cargo build --verbose
cargo test --verbose

# For the C ABI, we build in either debug or release mode, then build the C
# code appropriately and run it.
# TODO: Use an env var to separate these two notions!
CARGO_FLAGS=""
OPTIMIZATION=""
TARGET="debug"

if [[ "${RELEASE}" = true ]]; then
    CARGO_FLAGS="--release"
    OPTIMIZATION="-O1"
    TARGET="release"
fi

cd ../c-certitude
cargo build --verbose ${CARGO_FLAGS}
clang -L target/${TARGET} -framework Security -framework CoreFoundation -lSystem -lc -lm -lc_certitude "${OPTIMIZATION}" test/test.c
./a.out
