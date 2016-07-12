# BoringSSL

## Info
- Name: BoringSSL
- URL: https://boringssl.googlesource.com/boringssl
- License: BSDish
- License File: src/LICENSE

# Description
This is BoringSSL, a fork of OpenSSL. See
https://www.imperialviolet.org/2014/06/20/boringssl.html

# Rolling
This package should be in sync with [chromium-stable](https://boringssl.googlesource.com/boringssl/+/chromium-stable)

For rolling a new version, both Perl and Go must be installed on the system,
as they are used to generate code.

After rolling the current version from the chromium_stable branch, run:
```sh
python src/util/generate_build_files.py bazel
```
