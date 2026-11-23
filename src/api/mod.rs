//! Typed high-level API contract for `saml-rs`.
//!
//! Artifact binding is not part of the high-level browser SSO request binding
//! contract.
//!
//! ```compile_fail
//! use saml_rs::SsoRequestBinding;
//!
//! let binding = SsoRequestBinding::Artifact;
//! ```
//!
//! ```compile_fail
//! use saml_rs::{
//!     AuthnRequest, NameId, Received, RespondSso, ServiceProvider, SpDescriptor, SsoAssertion,
//! };
//!
//! let sp: ServiceProvider = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let name_id: NameId = unreachable!();
//!
//! let _ = sp.respond_sso(&peer, &request, SsoAssertion::new(name_id), RespondSso::post());
//! ```
//!
//! ```compile_fail
//! use saml_rs::{IdentityProvider, IdpDescriptor, StartSso};
//!
//! let idp: IdentityProvider = unreachable!();
//! let peer: IdpDescriptor = unreachable!();
//!
//! let _ = idp.start_sso(&peer, StartSso::post());
//! ```
//!
//! An HTTP-Artifact response is issued with `respond_sso_artifact`, which
//! stores it. `respond_sso` does not take those options, and
//! `respond_sso_artifact` does not take HTTP-POST options.
//!
//! ```compile_fail
//! use saml_rs::{
//!     ArtifactDelivery, AuthnRequest, IdentityProvider, NameId, Received, RespondSso,
//!     SpDescriptor, SsoAssertion,
//! };
//!
//! let idp: IdentityProvider = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let name_id: NameId = unreachable!();
//!
//! let options = RespondSso::artifact(ArtifactDelivery::redirect(0));
//! let _ = idp.respond_sso(&peer, &request, SsoAssertion::new(name_id), options);
//! ```
//!
//! ```compile_fail
//! use saml_rs::{
//!     AuthnRequest, IdentityProvider, IssuedArtifacts, NameId, Received, RespondSso, SpDescriptor,
//!     SsoAssertion,
//! };
//!
//! let idp: IdentityProvider = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let name_id: NameId = unreachable!();
//! let mut issued = IssuedArtifacts::expire_after(std::time::Duration::from_secs(60));
//! let assertion = SsoAssertion::new(name_id);
//!
//! let _ = idp.respond_sso_artifact(&peer, &request, assertion, RespondSso::post(), &mut issued);
//! ```
//!
//! ```compile_fail
//! use saml_rs::{CommonDomainCookieLifetime, RememberIdentityProvider, ServiceProvider};
//!
//! let sp: ServiceProvider = unreachable!();
//! let _ = sp.common_domain_cookie(RememberIdentityProvider::new(
//!     "example.org",
//!     CommonDomainCookieLifetime::Session,
//! ));
//! ```
//!
//! Name identifier management over SOAP is an identity-provider operation.
//! The service provider cannot send or answer it.
//!
//! ```compile_fail
//! use saml_rs::{
//!     NameId, NameIdChange, ServiceProvider, SoapChannel, SpDescriptor, StartNameIdManagement,
//! };
//!
//! let sp: ServiceProvider = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let name_id: NameId = unreachable!();
//! let channel: SoapChannel = unreachable!();
//!
//! let _ = sp.start_name_id_management(
//!     &peer,
//!     &name_id,
//!     &NameIdChange::Terminate,
//!     StartNameIdManagement::new(),
//!     channel,
//! );
//! ```
//!
//! ```compile_fail
//! use saml_rs::{SamlValidationContext, ServiceProvider, SoapChannel, SpDescriptor};
//!
//! let sp: ServiceProvider = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let channel: SoapChannel = unreachable!();
//! let validation: SamlValidationContext<'static> = unreachable!();
//!
//! let _ = sp.receive_name_id_management(&peer, "", channel, validation);
//! ```

mod artifact;
mod idp;
mod name_id_management;
mod options;
mod peer;
mod requested_subject;
mod response_acs;
mod slo;
mod sp;
mod sso_outcome;

use crate::error::SamlError;

pub use idp::IdentityProvider;
pub use name_id_management::NameIdManagementRedirectReceipt;
pub use options::{
    ForceAuthn, IsPassive, MessageDelivery, ReceiveNameIdManagement, RespondNameIdManagement,
    RespondSlo, RespondSso, StartNameIdManagement, StartSlo, StartSso,
};
pub use sp::ServiceProvider;
pub use sso_outcome::{SsoAssertion, SsoOutcome};
