//! Compatibility API and low-level protocol helpers.
//!
//! Prefer the crate-root [`crate::Saml`] facade for new high-level browser SSO
//! and SLO flows. Import from this module when you need direct access to the
//! existing entity, flow, metadata, and logout building blocks.
//!
//! The typed [`crate::Saml`] API is the recommended starting point for new
//! browser SSO and SLO integrations because it makes role state, pending
//! requests, browser input, and validation policy explicit. This module keeps
//! the lower-level compatibility surface public for migrations from earlier
//! `saml-rs` releases, unusual interoperability requirements, conformance
//! tests, and callers that need to work directly with SAML XML.
//!
//! Raw APIs expose compatibility types such as [`FlowResult`],
//! [`BindingContext`], [`HttpRequest`], and [`EntitySetting`]. Because those
//! types sit closer to protocol messages, callers may need to enforce
//! correlation, replay protection, RelayState checks, comparison of a message
//! `Destination` with the actual receiving endpoint, and validation policy
//! that typed flows model directly. In particular, a successful raw logout
//! parse is not a claim that `Destination` was checked: the raw parser receives
//! no local endpoint context.
//!
//! ```no_run
//! use saml_rs::raw::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
//! use saml_rs::raw::{Binding, EntitySetting, IdentityProvider, ServiceProvider};
//!
//! # fn main() -> Result<(), saml_rs::SamlError> {
//! let idp = IdentityProvider::from_config(
//!     &IdpMetadataConfig {
//!         entity_id: "https://idp.example.com/metadata".into(),
//!         single_sign_on_service: vec![Endpoint::new(
//!             Binding::Redirect,
//!             "https://idp.example.com/sso",
//!         )],
//!         ..Default::default()
//!     },
//!     EntitySetting::default(),
//! )?;
//! let sp = ServiceProvider::from_config(
//!     &SpMetadataConfig {
//!         entity_id: "https://sp.example.com/metadata".into(),
//!         assertion_consumer_service: vec![Endpoint::new(
//!             Binding::Post,
//!             "https://sp.example.com/acs",
//!         )],
//!         ..Default::default()
//!     },
//!     EntitySetting::default(),
//! )?;
//!
//! let request = sp.create_login_request(&idp, Binding::Redirect, None)?;
//! # let _ = request;
//! # Ok(()) }
//! ```

pub use crate::constants::Binding;
pub use crate::entity::{BindingContext, EntitySetting, User};
pub use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
pub use crate::idp::{IdentityProvider, LoginResponseOptions};
pub use crate::logout;
pub use crate::metadata;
pub use crate::sp::{LoginRequestOptions, ServiceProvider};
pub use crate::util::Value;
pub use crate::xml::{ExtractorField, LocalPath};
