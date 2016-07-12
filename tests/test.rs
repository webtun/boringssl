extern crate boringssl;


#[test]
fn it_compiles() {
    let mut ssl_ctx = match boringssl::Context::new() {
        Ok(ctx) => ctx,
        Err(_) => {
            panic!("SSL_CTX failed");
        }
    };

    ssl_ctx.set_min_version(boringssl::TLS1_2_VERSION);
    ssl_ctx.set_verify(boringssl::VerifyMode::None);
    ssl_ctx.enable_signed_cert_timestamps();
    ssl_ctx.enable_ocsp_stapling();
    ssl_ctx.enable_tls_channel_id();
}
