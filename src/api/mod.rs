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
//! ```compile_fail
//! use saml_rs::{CommonDomainCookieLifetime, RememberIdentityProvider, Saml, Sp};
//!
//! let sp: Saml<Sp> = unreachable!();
//! let _ = sp.remember_identity_provider(RememberIdentityProvider::new(
//!     "example.org",
//!     CommonDomainCookieLifetime::Session,
//! ));
//! ```

mod artifact;
mod idp;
mod options;
mod paos;
mod raw_mapping;
mod slo;
mod sp;

use crate::config::{validated_idp_issuance_lifetime, IdpConfig, SpConfig};
use crate::entity::EntitySetting;
use crate::error::SamlError as Error;
use crate::idp::IdentityProvider;
use crate::sp::ServiceProvider;

use raw_mapping::{raw_idp_metadata_config, raw_sp_metadata_config};

pub use options::{
    ForceAuthn, IsPassive, LogoutSigning, RespondSlo, RespondSso, StartSlo, StartSso,
};
pub use paos::{
    HttpHeader, PaosAuthnRequest, PaosClientRequest, PaosHttpResponse, PaosSsoResponse,
    PendingPaosSso, PendingPaosSsoSnapshot, SoapFault, StartPaosSso, StartedPaosSso,
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

/// Error type returned by the typed SAML API.
pub type SamlError = Error;

impl Saml {
    /// Build a typed Service Provider facade.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the SP config cannot be converted into raw
    /// settings or metadata, including missing metadata, missing keys, or
    /// unsupported crypto configuration.
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError> {
        let setting = EntitySetting::try_from(&config)?;
        let raw_config = raw_sp_metadata_config(&config);
        let service_provider = ServiceProvider::from_config(&raw_config, setting)?;
        Ok(Saml(Sp { service_provider }))
    }

    /// Build a typed Identity Provider facade.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the IdP config cannot be converted into raw
    /// settings or metadata, including an invalid issuance lifetime, missing
    /// metadata, missing keys, or unsupported crypto configuration.
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError> {
        let issuance_lifetime = validated_idp_issuance_lifetime(config.issuance_lifetime)?;
        let setting = EntitySetting::try_from(&config)?;
        let raw_config = raw_idp_metadata_config(&config);
        let identity_provider = IdentityProvider::from_config(&raw_config, setting)?;
        Ok(Saml(Idp {
            identity_provider,
            issuance_lifetime,
        }))
    }
}
