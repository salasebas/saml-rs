//! Deprecated compatibility API and low-level protocol helpers.
//!
//! The raw API is deprecated and is removed in the next minor release. Each
//! raw message function warns with its typed replacement on the crate-root
//! [`crate::Saml`] facade, which makes role state, pending requests, browser
//! input, and validation policy explicit:
//!
//! | Deprecated raw function | Typed replacement |
//! | --- | --- |
//! | [`ServiceProvider::create_login_request`] | [`Saml::<Sp>::start_sso`](crate::Saml::start_sso) |
//! | [`ServiceProvider::parse_login_response_with_request_id`] | [`Saml::<Sp>::finish_sso`](crate::Saml::finish_sso) |
//! | [`ServiceProvider::parse_unsolicited_login_response`] | [`Saml::<Sp>::accept_unsolicited_sso`](crate::Saml::accept_unsolicited_sso) |
//! | [`IdentityProvider::parse_login_request`] | [`Saml::<Idp>::receive_sso`](crate::Saml::receive_sso) |
//! | [`IdentityProvider::create_login_response`] | [`Saml::<Idp>::respond_sso`](crate::Saml::respond_sso), or [`Saml::<Idp>::initiate_sso`](crate::Saml::initiate_sso) for an unsolicited response |
//! | [`logout::create_logout_request`], [`logout::create_logout_request_with_id`] | `Saml::start_slo` |
//! | [`logout::parse_logout_request`] | `Saml::receive_slo` |
//! | [`logout::create_logout_response`], [`logout::create_logout_response_with_id`] | `Saml::respond_slo` |
//! | [`logout::parse_logout_response`], [`logout::parse_logout_response_without_request_id`] | `Saml::finish_slo` |
//! | [`flow()`] | The typed receive operation for the message |
//! | [`HttpRequest::redirect`] | [`Inbound::redirect`](crate::Inbound) with the raw query string |
//!
//! Raw APIs expose compatibility types such as [`FlowResult`],
//! [`BindingContext`], [`HttpRequest`], and [`EntitySetting`]. Because those
//! types sit closer to protocol messages, callers may need to enforce
//! correlation, replay protection, RelayState checks, comparison of a message
//! `Destination` with the actual receiving endpoint, and validation policy
//! that typed flows model directly. In particular, a successful raw logout
//! parse is not a claim that `Destination` was checked: the raw parser receives
//! no local endpoint context.

pub use crate::constants::Binding;
pub use crate::entity::{BindingContext, EntitySetting, User};
#[allow(deprecated)]
pub use crate::flow::flow;
pub use crate::flow::{FlowOptions, FlowResult, HttpRequest, SignatureCheck};
pub use crate::idp::{IdentityProvider, LoginResponseOptions};
pub use crate::logout;
pub use crate::sp::{LoginRequestOptions, ServiceProvider};
pub use crate::template::{LoginResponseAttribute, LoginResponseTemplate};
pub use crate::util::Value;
pub use crate::xml::{ExtractorField, LocalPath};
