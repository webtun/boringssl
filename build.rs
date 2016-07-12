extern crate gcc;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::path::Path;

#[derive(PartialEq,Debug)]
enum Context {
    None,
    Asm,
    Crypto,
    Ssl,
    Ignore,
}

#[allow(non_camel_case_types)]
#[derive(PartialEq,Debug)]
enum CryptoTarget {
    LinuxAarch64,
    LinuxArm,
    LinuxX86,
    LinuxX86_64,
    MacX86,
    MacX86_64,
    WinX86,
    WinX86_64,
}

fn check_env(src: CryptoTarget) -> Context {
    let target = env::var("TARGET").unwrap();
    let t: Vec<&str> = target.split('-').collect();
    assert!(t.len() >= 3);

    // <arch><sub>-<vendor>-<sys>-<abi>, where:
    //  arch = x86, arm, thumb, mips, etc.
    //  sub = for ex. on ARM: v5, v6m, v7a, v7m, etc.
    //  vendor = pc, apple, nvidia, ibm, etc.
    //  sys = none, linux, win32, darwin, cuda, etc.
    //  abi = eabi, gnu, android, macho, elf, etc.
    let src_target = match t[0] {
        "x86" => {
            match t[2] {
                "darwin" => CryptoTarget::MacX86,
                "linux" => CryptoTarget::LinuxX86,
                "win32" => CryptoTarget::WinX86,
                _ => panic!("unimplemented target {:?}", target),
            }
        }
        "x86_64" => {
            match t[2] {
                "darwin" => CryptoTarget::MacX86_64,
                "linux" => CryptoTarget::LinuxX86_64,
                "win32" => CryptoTarget::WinX86_64,
                _ => panic!("unimplemented target {:?}", target),
            }
        }
        _ => panic!("unimplemented target {:?}", target),
    };

    if src == src_target {
        return Context::Asm;
    }
    Context::Ignore
}

fn get_filename(s: &mut String) -> String {
    // remove ," at the end
    let i = s.len() - 2;
    s.truncate(i);
    String::from("third_party/boringssl/") + &s[5..]
}

fn main() {
    // lists of source files
    let mut asm_src: Vec<String> = Vec::new();
    let mut crypto_src: Vec<String> = Vec::new();
    let mut ssl_src: Vec<String> = Vec::new();

    // parse generated bazel file
    let build_path = Path::new("third_party/boringssl/BUILD.generated.bzl");
    let build_file = match File::open(&build_path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open BUILD file: {}", why.description()),
        Ok(file) => file,
    };

    let reader = BufReader::new(build_file);
    let mut ctx = Context::None;
    for l in reader.lines() {
        let mut line = l.unwrap();

        // skip empty lines
        if line.is_empty() {
            continue;
        }

        // skip comments
        if line.starts_with("#") {
            continue;
        }

        if ctx == Context::None {
            if !line.ends_with(" = [") {
                panic!("invalid line {:?}", line);
            }

            // remove " = [" at the end
            let i = line.len() - 4;
            line.truncate(i);

            // match context
            ctx = match line.as_ref() {
                "crypto_headers" => Context::Ignore,
                "crypto_internal_headers" => Context::Ignore,
                "crypto_sources" => Context::Crypto,
                "crypto_sources_linux_aarch64" => check_env(CryptoTarget::LinuxAarch64),
                "crypto_sources_linux_arm" => check_env(CryptoTarget::LinuxArm),
                "crypto_sources_linux_x86" => check_env(CryptoTarget::LinuxX86),
                "crypto_sources_linux_x86_64" => check_env(CryptoTarget::LinuxX86_64),
                "crypto_sources_mac_x86" => check_env(CryptoTarget::MacX86),
                "crypto_sources_mac_x86_64" => check_env(CryptoTarget::MacX86_64),
                "crypto_sources_win_x86" => check_env(CryptoTarget::WinX86),
                "crypto_sources_win_x86_64" => check_env(CryptoTarget::WinX86_64),
                "ssl_headers" => Context::Ignore,
                "ssl_internal_headers" => Context::Ignore,
                "ssl_sources" => Context::Ssl,
                "tool_sources" => Context::Ignore,
                "tool_headers" => Context::Ignore,
                s => panic!("unknown source file context {:?}", s),
            };
        } else {
            if line.starts_with("    \"") {
                // add file to respective sources list
                match ctx {
                    Context::Ignore => continue,
                    Context::Asm => asm_src.push(get_filename(&mut line)),
                    Context::Crypto => crypto_src.push(get_filename(&mut line)),
                    Context::Ssl => ssl_src.push(get_filename(&mut line)),
                    _ => panic!("how did that happen?! {:?}", ctx),
                };
            } else if line == "]" {
                // context end
                ctx = Context::None;
            } else {
                panic!("unable to parse line: {:?}", line);
            }
        }
    }

    // compile config
    let mut boringssl = gcc::Config::new();
    boringssl.include("third_party/boringssl/src/include")
        .define("BORINGSSL_IMPLEMENTATION", None)
        //.define("BORINGSSL_NO_STATIC_INITIALIZER", None) // not yet
        .define("OPENSSL_SMALL", None)
        .define("_XOPEN_SOURCE", Some("700"))
        .flag("-std=c99");

    // add source files
    for src in &asm_src {
        boringssl.file(src);
    }
    for src in &crypto_src {
        boringssl.file(src);
    }
    for src in &ssl_src {
        boringssl.file(src);
    }

    // compile and link static lib
    boringssl.compile("libboringssl.a");
}
