#![allow(non_camel_case_types)]

use std::os::raw::{c_void, c_char, c_int};

pub type SSL_METHOD = c_void;

/// SSL_CTX objects manage shared state and configuration between multiple TLS
/// or DTLS connections. Whether the connections are TLS or DTLS is selected by
/// an SSL_METHOD on creation.
/// SSL_CTX are reference-counted and may be shared by connections across
/// multiple threads. Once shared, functions which change the SSL_CTX's
/// configuration may not be used.
pub type SSL_CTX = c_void;

/// An SSL object represents a single TLS or DTLS connection.
/// Although the shared SSL_CTX is thread-safe, an SSL is not thread-safe and
/// may only be used on one thread at a time.
pub type SSL = c_void;

pub const TLS1_VERSION: u16 = 0x0301;
pub const TLS1_1_VERSION: u16 = 0x0302;
pub const TLS1_2_VERSION: u16 = 0x0303;
pub const TLS1_3_VERSION: u16 = 0x0304;

// certificate verification modes
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
pub const SSL_VERIFY_PEER_IF_NO_OBC: c_int = 4;

extern "C" {
    /// TLS_method is the SSL_METHOD used for TLS (and SSLv3) connections.
    pub fn TLS_method() -> *const SSL_METHOD;

    /// SSL_CTX_new returns a newly-allocated SSL_CTX with default settings or NULL on error.
    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;

    /// SSL_CTX_free releases memory associated with ctx.
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);

    /// Configures the cipher list for ctx, evaluating str as a cipher string.
    /// It returns one on success and zero on failure.
    pub fn SSL_CTX_set_cipher_list(ssl: *mut SSL_CTX, list: *const c_char) -> c_int;

    /// Sets the minimum protocol version for ctx to version.
    pub fn SSL_CTX_set_min_version(ssl: *mut SSL_CTX, version: u16);

    /// Configures certificate verification behavior.
    /// mode is one of the SSL_VERIFY_* values.
    /// callback, if not NULL, is used to customize certificate verification.
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX,
                              mode: c_int,
                              callback: Option<extern "C" fn(c_int, *mut c_void) -> c_int>);

    /// Enables SCT requests on all client SSL objects created from ctx.
    /// See https://tools.ietf.org/html/rfc6962.
    pub fn SSL_CTX_enable_signed_cert_timestamps(ctx: *mut SSL_CTX);

    /// Enables OCSP stapling on all client SSL objects created from ctx.
    pub fn SSL_CTX_enable_ocsp_stapling(ctx: *mut SSL_CTX);

    /// Either configures a TLS server to accept TLS Channel IDs from clients,
    /// or configures a client to send TLS Channel IDs to a server.
    /// It returns 1.
    pub fn SSL_CTX_enable_tls_channel_id(ctx: *mut SSL_CTX) -> c_int;
}

extern "C" {
    /// SSL_new returns a newly-allocated SSL using ctx or NULL on error.
    /// The new connection inherits settings from ctx at the time of creation.
    /// Settings may also be individually configured on the connection.
    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    /// SSL_free releases memory associated with ssl.
    pub fn SSL_free(ssl: *mut SSL);

    /// SSL_set_connect_state configures ssl as a client.
    pub fn SSL_set_connect_state(ssl: *mut SSL);

    /// SSL_do_handshake starts or continues the current handshake.
    /// If there is none or the handshake has completed or False Started, it
    /// returns one. Otherwise, it returns <= 0. The caller should pass the
    /// value into SSL_get_error to determine how to proceed.
    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;

    /// SSL_connect configures ssl as a client, if unconfigured, and calls
    /// SSL_do_handshake.
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;

    /// SSL_set_tlsext_host_name, for a client, configures ssl to advertise name
    /// in the server_name extension. It returns one on success and zero on error.
    pub fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_int;

    /// SSL_set_bio configures ssl to read from rbio and write to wbio.
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);

    /// SSL_set_fd configures ssl to read from and write to fd.
    /// It returns one on success and zero on allocation error.
    /// The caller retains ownership of fd.
    /// On Windows, fd is cast to a SOCKET and used with Winsock APIs.
    pub fn SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int;

    /// SSL_read reads up to num bytes from ssl into buf.
    /// It implicitly runs any pending handshakes, including renegotiations when
    /// enabled. On success, it returns the number of bytes read. Otherwise, it
    /// returns <= 0. The caller should pass the value into SSL_get_error to
    /// determine how to proceed.
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;

    /// SSL_pending returns the number of bytes available in ssl.
    /// It does not read from the transport.
    pub fn SSL_pending(ssl: *const SSL) -> c_int;

    /// SSL_write writes up to num bytes from buf into ssl.
    /// It implicitly runs any pending handshakes, including renegotiations when
    /// enabled. On success, it returns the number of bytes read. Otherwise, it
    /// returns <= 0. The caller should pass the value into SSL_get_error to
    /// determine how to proceed.
    /// In TLS, a non-blocking SSL_write differs from non-blocking write in that
    /// a failed SSL_write still commits to the data passed in.
    /// When retrying, the caller must supply the original write buffer
    /// (or a larger one containing the original as a prefix).
    /// By default, retries will fail if they also do not reuse the same buf
    /// pointer.
    /// By default, in TLS, SSL_write will not return success until all num
    /// bytes are written.
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;

    /// SSL_shutdown shuts down ssl. On success, it completes in two stages.
    /// First, it returns 0 if ssl completed uni-directional shutdown;
    /// close_notify has been sent, but the peer's close_notify has not been
    /// received. Most callers may stop at this point. For bi-directional
    /// shutdown, call SSL_shutdown again. It returns 1 if close_notify has been
    /// both sent and received.
    ///  If the peer's close_notify arrived first, the first stage is skipped.
    /// SSL_shutdown will return 1 once close_notify is sent and skip 0.
    /// Callers only interested in uni-directional shutdown must therefore allow
    /// for the first stage returning either 0 or 1.
    /// SSL_shutdown returns -1 on failure. The caller should pass the return
    /// value into SSL_get_error to determine how to proceed.
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;

    /// SSL_get_error returns a SSL_ERROR_* value for the most recent operation
    /// on ssl. It should be called after an operation failed to determine
    /// whether the error was fatal and, if not, when to retry.
    pub fn SSL_get_error(ssl: *const SSL, ret_code: c_int) -> c_int;
}

pub const BIO_NOCLOSE: c_int = 0;
pub const BIO_CLOSE: c_int = 1;

pub type BIO_METHOD = c_void;
pub type BIO = c_void;

extern "C" {
    pub fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    pub fn BIO_free(bio: *mut BIO) -> c_int;
    pub fn BIO_read(bio: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    pub fn BIO_write(bio: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    pub fn BIO_new_socket(fd: c_int, close_flag: c_int) -> *mut BIO;
}


pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;
pub const SSL_ERROR_WANT_CHANNEL_ID_LOOKUP: c_int = 9;
pub const SSL_ERROR_PENDING_SESSION: c_int = 11;
pub const SSL_ERROR_PENDING_CERTIFICATE: c_int = 12;
pub const SSL_ERROR_WANT_PRIVATE_KEY_OPERATION: c_int = 13;

extern "C" {
    pub fn ERR_get_error() -> u32;
    pub fn ERR_peek_error() -> u32;
    pub fn ERR_lib_error_string(err: u32) -> *const c_char;
    pub fn ERR_reason_error_string(err: u32) -> *const c_char;
    pub fn ERR_clear_error();
}
