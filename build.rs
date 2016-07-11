// TODO(js): auto-build boringssl libs
fn main() {
    println!("cargo:rustc-link-search={}",
             "third_party/boringssl/bin/crypto/");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-search={}",
             "third_party/boringssl/bin/ssl/");
    println!("cargo:rustc-link-lib=static=ssl");
}
