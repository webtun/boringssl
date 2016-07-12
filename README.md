# BoringSSL Rust Bindings

[![Build Status](https://travis-ci.org/webtun/boringssl.svg?branch=master)](https://travis-ci.org/webtun/boringssl)

This package provides bindings for [BoringSSL](https://boringssl.googlesource.com/boringssl/).
BoringSSL is statically linked by this package.
It tracks the [chromium-stable](https://boringssl.googlesource.com/boringssl/+/chromium-stable) branch and should therefore use the same version of BoringSSL as the latest Chrome / Chromium release.

## Third-Party Code
This package includes auto-generated code from boringssl, which is separately licensed (BSDish Licenses).
See [boringssl's LICENSE](https://boringssl.googlesource.com/boringssl/+/chromium-stable/LICENSE) for details.
