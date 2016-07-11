#![allow(dead_code)]

use std::os::raw::{c_int, c_void};
use std::os::unix::io::RawFd;
use std::ffi::{CString, CStr};
use std::str;
use std::result;
use std::error;
use std::fmt;

mod ffi;

/// TLS Versions
pub use self::ffi::{TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION};

#[derive(Debug)]
pub enum VerifyMode {
    None = ffi::SSL_VERIFY_NONE as isize,
    Peer = ffi::SSL_VERIFY_PEER as isize,
}

#[derive(Debug)]
pub enum Error {
    /// The operation succeeded.
    None, // TODO: remove

    /// The operation failed within the library.
    /// The caller may inspect the error queue for more information.
    Ssl,

    /// The operation failed attempting to read from the transport.
    /// The caller may retry the operation when the transport is ready for reading.
    WantRead,

    /// The operation failed attempting to write to the transport.
    /// The caller may retry the operation when the transport is ready for writing.
    WantWrite,

    /// The operation failed in calling the cert_cb or client_cert_cb.
    /// The caller may retry the operation when the callback is ready to return
    /// a certificate or one has been configured externally.
    WantX509Lookup,

    /// The operation failed externally to the library.
    /// The caller should consult the system-specific error mechanism.
    /// It may also be signaled if the transport returned EOF, in which case the
    /// operation's return value will be zero.
    Syscall,

    /// The operation failed because the connection was cleanly shut down with a
    /// close_notify alert.
    ZeroReturn,

    /// The operation failed attempting to connect the transport.
    /// The caller may retry the operation when the transport is ready.
    WantConnect,

    /// The operation failed attempting to accept a connection from the transport.
    /// The caller may retry the operation when the transport is ready.
    WantAccept,

    /// The operation failed looking up the Channel ID key.
    /// The caller may retry the operation when channel_id_cb is ready to return
    /// a key or one has been configured with SSL_set1_tls_channel_id.
    WantChannelIdLookup,

    /// The operation failed because the session lookup callback indicated the
    /// session was unavailable.
    /// The caller may retry the operation when lookup has completed.
    PendingSession,

    /// The operation failed because the early callback indicated certificate
    /// lookup was incomplete.
    /// The caller may retry the operation when lookup has completed.
    /// Note: when the operation is retried, the early callback will not be
    /// called a second time.
    PendingCertificate,

    /// The operation failed because a private key operation was unfinished.
    /// The caller may retry the operation when the private key operation is
    /// complete.
    WantPrivateKeyOperation,

    AllocationFailed, // TODO
}

pub type Result<T> = result::Result<T, Error>;

// TODO lock on first connection
pub struct Context {
    ctx: *mut ffi::SSL_CTX,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
    }
}

impl Context {
    pub fn new() -> Result<Context> {
        unsafe {
            let method = ffi::TLS_method();
            let ctx = ffi::SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(Error::AllocationFailed);
            }
            Ok(Context { ctx: ctx })
        }
    }

    pub fn set_cipher_list(&mut self, list: &str) {
        let cstr = CString::new(list).unwrap();
        let ret_code = unsafe { ffi::SSL_CTX_set_cipher_list(self.ctx, cstr.as_ptr()) };
        if ret_code != 1 {
            panic!("{:?}", SslError::get());
        }
        // ret_code // TODO
    }

    pub fn set_min_version(&mut self, version: u16) {
        unsafe {
            ffi::SSL_CTX_set_min_version(self.ctx, version);
        };
    }

    pub fn set_verify(&mut self, mode: VerifyMode) {
        unsafe {
            ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, None);
        };
    }

    pub fn enable_signed_cert_timestamps(&mut self) {
        unsafe {
            ffi::SSL_CTX_enable_signed_cert_timestamps(self.ctx);
        };
    }

    pub fn enable_ocsp_stapling(&mut self) {
        unsafe {
            ffi::SSL_CTX_enable_ocsp_stapling(self.ctx);
        };
    }

    pub fn enable_tls_channel_id(&mut self) {
        unsafe {
            let ret_code = ffi::SSL_CTX_enable_tls_channel_id(self.ctx);
            assert_eq!(1, ret_code); // always returns 1
        }
    }

    // pub fn connect_socket(&self, fd: RawFd) -> Result<Connection> {
    // let conn = try!(Connection::new(self));
    //
    // let bio = try!(Bio::new_socket(fd));
    // conn.set_bio(bio);
    //
    // if conn.set_fd(fd) != 1 {
    // return Err(Error::AllocationFailed);
    // }
    //
    // let ret = conn.connect();
    // println!("ret code {:?}", ret);
    //
    // match ret {
    // 1 => Ok(conn),
    // n => Err(conn.get_error(n)),
    // }
    // }
}

pub struct Client {
    ssl: *mut ffi::SSL,
}

impl Drop for Client {
    fn drop(&mut self) {
        println!("DROP"); // TODO
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Client {
    fn new(ctx: &Context) -> Result<Client> {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        if ssl.is_null() {
            return Err(Error::AllocationFailed);
        }

        // configure as client
        unsafe { ffi::SSL_set_connect_state(ssl) };
        Ok(Client { ssl: ssl })
    }

    pub fn new_socket(ctx: &Context, fd: RawFd) -> Result<Client> {
        let mut conn = try!(Client::new(ctx));

        // let bio = try!(Bio::new_socket(fd));
        // conn.set_bio(bio);

        if conn.set_fd(fd) != 1 {
            return Err(Error::AllocationFailed);
        }

        Ok(conn)
    }

    fn set_bio(&mut self, bio: Bio) {
        unsafe { ffi::SSL_set_bio(self.ssl, bio.bio, bio.bio) };
    }

    fn set_fd(&mut self, fd: RawFd) -> c_int {
        unsafe { ffi::SSL_set_fd(self.ssl, fd) }
    }

    /// If <0 is returned, it must be called again when the underlying stream is
    /// ready to contiue the handshake.
    pub fn handshake(&mut self) -> Result<()> {
        let ret_code = unsafe { ffi::SSL_do_handshake(self.ssl) };
        match ret_code {
            1 => Ok(()),
            n => Err(self.get_error(n)),
        }
    }

    fn get_error(&mut self, ret_code: c_int) -> Error {
        let err_code = unsafe { ffi::SSL_get_error(self.ssl, ret_code) };
        match err_code {
            ffi::SSL_ERROR_NONE => Error::None,
            ffi::SSL_ERROR_SSL => Error::Ssl,
            ffi::SSL_ERROR_WANT_READ => Error::WantRead,
            ffi::SSL_ERROR_WANT_WRITE => Error::WantWrite,
            ffi::SSL_ERROR_WANT_X509_LOOKUP => Error::WantX509Lookup,
            ffi::SSL_ERROR_SYSCALL => Error::Syscall,
            ffi::SSL_ERROR_ZERO_RETURN => Error::ZeroReturn,
            ffi::SSL_ERROR_WANT_CONNECT => Error::WantConnect,
            ffi::SSL_ERROR_WANT_ACCEPT => Error::WantAccept,
            ffi::SSL_ERROR_WANT_CHANNEL_ID_LOOKUP => Error::WantChannelIdLookup,
            ffi::SSL_ERROR_PENDING_SESSION => Error::PendingSession,
            ffi::SSL_ERROR_PENDING_CERTIFICATE => Error::PendingCertificate,
            ffi::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION => Error::WantPrivateKeyOperation,
            _ => unimplemented!(),
        }
    }

    /// Configures ssl to advertise name in the server_name extension (RFC 3546).
    pub fn set_hostname(&mut self, hostname: &str) -> Result<()> {
        let cstr = CString::new(hostname).unwrap();
        let ret_code = unsafe { ffi::SSL_set_tlsext_host_name(self.ssl, cstr.as_ptr()) };
        match ret_code {
            1 => Ok(()),
            n => Err(self.get_error(n)),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let ret_code =
            unsafe { ffi::SSL_read(self.ssl, buf.as_ptr() as *mut c_void, buf.len() as c_int) };
        if ret_code > 0 {
            Ok(ret_code as usize)
        } else {
            Err(self.get_error(ret_code))
        }
    }

    pub fn pending(&mut self) -> usize {
        let num = unsafe { ffi::SSL_pending(self.ssl) };
        num as usize
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let ret_code =
            unsafe { ffi::SSL_write(self.ssl, buf.as_ptr() as *const c_void, buf.len() as c_int) };
        if ret_code > 0 {
            Ok(ret_code as usize)
        } else {
            Err(self.get_error(ret_code))
        }
    }
}

pub struct Bio {
    bio: *mut ffi::BIO,
}

impl Bio {
    fn new_socket(fd: RawFd) -> Result<Bio> {
        unsafe {
            let bio = ffi::BIO_new_socket(fd, ffi::BIO_NOCLOSE);
            if bio.is_null() {
                return Err(Error::AllocationFailed);
            }
            Ok(Bio { bio: bio })
        }
    }
}

/// SslError is a packed representation of an internal error in the SSL library.
/// When a function fails, it adds an entry to a per-thread error queue.
/// SslError::get() can be used to retrive those items in the queue.
/// As an error might occour deep in the call queue, multiple entries might be
/// added to the error queue.
/// The first (least recent) error is the most specific.
#[derive(Debug)]
pub struct SslError {
    packed: u32,
}

impl fmt::Display for SslError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.lib(), self.reason())
    }
}

impl error::Error for SslError {
    fn description(&self) -> &str {
        "BoringSSL Internal Error"
    }
}

impl SslError {
    /// Gets the packed error code for the least recent error and removes that
    /// error from the queue. If there are no errors in the queue then it
    /// returns None.
    pub fn get() -> Option<SslError> {
        match unsafe { ffi::ERR_get_error() } {
            0 => None,
            err => Some(SslError { packed: err }),
        }
    }

    /// Acts like get(), but does not remove the error from the error queue.
    pub fn peek() -> Option<SslError> {
        match unsafe { ffi::ERR_peek_error() } {
            0 => None,
            err => Some(SslError { packed: err }),
        }
    }

    /// Returns a string representation of the library that generated the error.
    pub fn lib(&self) -> &'static str {
        let bs = unsafe {
            let c_str = ffi::ERR_lib_error_string(self.packed);
            CStr::from_ptr(c_str).to_bytes()
        };
        str::from_utf8(bs).unwrap()
    }

    /// Returns a string representation of the reason for the error.
    pub fn reason(&self) -> &'static str {
        let bs = unsafe {
            let c_str = ffi::ERR_reason_error_string(self.packed);
            CStr::from_ptr(c_str).to_bytes()
        };
        str::from_utf8(bs).unwrap()
    }

    /// Clears the error queue for the current thread.
    pub fn clear() {
        unsafe { ffi::ERR_clear_error() }
    }
}
