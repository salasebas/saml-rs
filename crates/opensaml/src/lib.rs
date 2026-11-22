#![forbid(unsafe_code)]
//! Maintained re-export of [`saml-rs`](https://crates.io/crates/saml-rs).
//!
//! ```
//! use opensaml::{OpenSamlError, ServiceProvider};
//!
//! let _: Option<ServiceProvider> = None;
//! #[allow(deprecated)]
//! let _: Option<OpenSamlError> = None;
//! ```

pub use saml_rs::*;

/// Deprecated alias for [`SamlError`].
#[deprecated(since = "0.2.0", note = "use `SamlError` instead")]
pub type OpenSamlError = saml_rs::SamlError;
