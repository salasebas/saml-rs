//! Response rendering for a Web Browser SSO response stored for an artifact.

use super::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::constants::Binding;
use crate::entity::User;
use crate::error::SamlError;
use crate::sp::ServiceProvider;

impl IdentityProvider {
    /// SAML `Response` ID and XML to store for an HTTP-Artifact.
    ///
    /// The XML is the HTTP-POST response for the assertion consumer in
    /// `overrides`, including its signature. A status other than top-level
    /// success omits assertions.
    pub(crate) fn render_artifact_sso_response(
        &self,
        sp: &ServiceProvider,
        user: &User,
        in_response_to: Option<&str>,
        overrides: LoginResponseOverrides<'_>,
    ) -> Result<(String, String), SamlError> {
        let context = self.create_login_response_with_overrides(
            sp,
            Binding::Post,
            user,
            &LoginResponseOptions {
                in_response_to,
                relay_state: None,
                encrypt_then_sign: false,
                custom: None,
            },
            overrides,
        )?;
        let xml = crate::binding::base64_decode(&context.context)?;
        let xml = String::from_utf8(xml).map_err(|err| SamlError::Xml(err.to_string()))?;
        Ok((context.id, xml))
    }
}
