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
//! use saml_rs::{AuthnRequest, Received, RespondSso, Saml, Sp, SpDescriptor, Subject};
//!
//! let sp: Saml<Sp> = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let subject: Subject = unreachable!();
//!
//! let _ = sp.respond_sso(&peer, &request, subject, RespondSso::post());
//! ```
//!
//! ```compile_fail
//! use saml_rs::{Idp, IdpDescriptor, Saml, StartSso};
//!
//! let idp: Saml<Idp> = unreachable!();
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
//!     ArtifactDelivery, AuthnRequest, Idp, Received, RespondSso, Saml, SpDescriptor, Subject,
//! };
//!
//! let idp: Saml<Idp> = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let subject: Subject = unreachable!();
//!
//! let options = RespondSso::artifact(ArtifactDelivery::redirect(0));
//! let _ = idp.respond_sso(&peer, &request, subject, options);
//! ```
//!
//! ```compile_fail
//! use saml_rs::{
//!     AuthnRequest, Idp, IssuedArtifacts, Received, RespondSso, Saml, SpDescriptor, Subject,
//! };
//!
//! let idp: Saml<Idp> = unreachable!();
//! let peer: SpDescriptor = unreachable!();
//! let request: Received<AuthnRequest> = unreachable!();
//! let subject: Subject = unreachable!();
//! let mut issued = IssuedArtifacts::expire_after(std::time::Duration::from_secs(60));
//!
//! let _ = idp.respond_sso_artifact(&peer, &request, subject, RespondSso::post(), &mut issued);
//! ```
//!
//! ```compile_fail
//! use saml_rs::{CommonDomainCookieLifetime, RememberIdentityProvider, Saml, Sp};
//!
//! let sp: Saml<Sp> = unreachable!();
//! let _ = sp.remember_identity_provider(RememberIdentityProvider::new(
//!     "example.org",
//!     CommonDomainCookieLifetime::Session,
//! ));
//! ```
//!
//! Name identifier management over SOAP is an identity-provider operation.
//! The service provider cannot send or answer it.
//!
//! ```compile_fail
//! use saml_rs::{IdpDescriptor, NameId, NameIdChange, Saml, SoapChannel, Sp};
//!
//! let sp: Saml<Sp> = unreachable!();
//! let peer: IdpDescriptor = unreachable!();
//! let name_id: NameId = unreachable!();
//! let channel: SoapChannel = unreachable!();
//!
//! let _ = sp.start_name_id_management(&peer, &name_id, &NameIdChange::Terminate, channel);
//! ```
//!
//! ```compile_fail
//! use saml_rs::{IdpDescriptor, Saml, SamlValidationContext, SoapChannel, Sp};
//!
//! let sp: Saml<Sp> = unreachable!();
//! let peer: IdpDescriptor = unreachable!();
//! let channel: SoapChannel = unreachable!();
//! let validation: SamlValidationContext<'static> = unreachable!();
//!
//! let _ = sp.receive_name_id_management(&peer, "", channel, validation);
//! ```

mod artifact;
mod idp;
mod name_id_management;
mod options;
mod paos;
mod raw_mapping;
mod requested_subject;
mod response_acs;
mod slo;
mod sp;

use crate::config::{IdpConfig, SpConfig};
use crate::error::SamlError;
use crate::idp::IdentityProvider;
use crate::sp::ServiceProvider;

pub use name_id_management::ReceivedNameIdManagementRedirect;
pub use options::{
    ForceAuthn, IsPassive, LogoutSigning, MessageDelivery, ReceiveNameIdManagement,
    RespondNameIdManagement, RespondSlo, RespondSso, StartNameIdManagement, StartSlo, StartSso,
};
pub use paos::{
    HttpHeader, PaosAuthnRequest, PaosClientRequest, PaosHttpResponse, PaosSsoResponse,
    PendingPaosSso, PendingPaosSsoSnapshot, RespondPaosSso, SoapFault, StartPaosSso,
    StartedPaosSso,
};

/// Typed SAML facade for high-level browser SSO/SLO flows.
pub struct Saml<Role = Unknown>(Role);

/// Marker role used before a facade has been configured as an SP or IdP.
pub enum Unknown {}

/// Marker role for a Service Provider facade.
pub struct Sp {
    service_provider: ServiceProvider,
}

/// Marker role for an Identity Provider facade.
pub struct Idp {
    identity_provider: IdentityProvider,
    issuance_lifetime: time::Duration,
}

impl Saml {
    /// Build a typed Service Provider facade.
    ///
    /// # Errors
    ///
    /// Returns no error for a config [`SpConfigBuilder::build`] returned:
    /// `build` generates the same SP metadata and returns its errors.
    ///
    /// [`SpConfigBuilder::build`]: crate::SpConfigBuilder::build
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError> {
        let service_provider = config.to_service_provider()?;
        Ok(Saml(Sp { service_provider }))
    }

    /// Build a typed Identity Provider facade.
    ///
    /// # Errors
    ///
    /// Returns no error for a config [`IdpConfigBuilder::build`] returned:
    /// `build` generates the same IdP metadata and returns its errors.
    ///
    /// [`IdpConfigBuilder::build`]: crate::IdpConfigBuilder::build
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError> {
        let identity_provider = config.to_identity_provider()?;
        Ok(Saml(Idp {
            identity_provider,
            issuance_lifetime: config.issuance_period(),
        }))
    }
}
