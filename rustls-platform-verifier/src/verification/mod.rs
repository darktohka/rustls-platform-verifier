#[cfg(target_vendor = "apple")]
use std::sync::Arc;

#[cfg(any(
    all(
        any(unix, target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_vendor = "apple"),
    ),
    windows
))]
mod others;

#[cfg(any(
    all(
        any(unix, target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_vendor = "apple"),
    ),
    windows
))]
pub use others::Verifier;

#[cfg(target_vendor = "apple")]
mod apple;

#[cfg(target_vendor = "apple")]
pub use apple::Verifier;

#[cfg(target_os = "android")]
pub(crate) mod android;

#[cfg(target_os = "android")]
pub use android::Verifier;

/// An EKU was invalid for the use case of verifying a server certificate.
///
/// This error is used primarily for tests.
#[derive(Debug, PartialEq)]
pub(crate) struct EkuError;

impl std::fmt::Display for EkuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate had invalid extensions")
    }
}

impl std::error::Error for EkuError {}

// Log the certificate we are verifying so that we can try and find what may be wrong with it
// if we need to debug a user's situation.
fn log_server_cert(_end_entity: &rustls::pki_types::CertificateDer<'_>) {
    #[cfg(feature = "cert-logging")]
    {
        use base64::Engine;
        log::debug!(
            "verifying certificate: {}",
            base64::engine::general_purpose::STANDARD.encode(_end_entity.as_ref())
        );
    }
}

// Unknown certificate error shorthand. Used when we need to construct an "Other" certificate
// error with a platform specific error message.
#[cfg(target_vendor = "apple")]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::from(Box::from(reason.into())),
    )))
}

#[cfg(target_os = "android")]
pub const ALLOWED_EKUS: &[&str] = &["1.3.6.1.5.5.7.3.1"];
