//! Response rendering for the SOAP leg of Enhanced Client/Proxy SSO.

use super::{
    IdentityProvider, LoginResponseOptions, LoginResponseOverrides, RenderedLoginResponse,
};
use crate::constants::Binding;
use crate::entity::User;
use crate::error::SamlError;
use crate::model::{Attribute, AuthnContextReference, RequestedAuthnContext, Status};
use crate::sp::{ServiceProvider, WebBrowserSsoProducer};

pub(crate) struct PaosSsoResponseInput<'a> {
    pub(crate) sp: &'a ServiceProvider,
    pub(crate) acs: &'a str,
    pub(crate) in_response_to: &'a str,
    pub(crate) user: &'a User,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) sp_provided_id: Option<&'a str>,
    pub(crate) issuance_lifetime: time::Duration,
    pub(crate) status: Option<&'a Status>,
    pub(crate) attributes: &'a [Attribute],
    pub(crate) authn_context: Option<&'a AuthnContextReference>,
    pub(crate) requested_authn_context: Option<&'a RequestedAuthnContext>,
}

impl IdentityProvider {
    /// SAML `Response` XML for the SOAP leg of Enhanced Client/Proxy SSO.
    ///
    /// The XML is the HTTP-POST response, including its signature, before the
    /// PAOS caller wraps it. A status other than top-level success omits
    /// assertions.
    pub(crate) fn render_paos_sso_response(
        &self,
        input: &PaosSsoResponseInput<'_>,
    ) -> Result<RenderedLoginResponse, SamlError> {
        let issued = self.create_login_response_with_overrides(
            input.sp,
            Binding::Post,
            input.user,
            &LoginResponseOptions {
                in_response_to: Some(input.in_response_to),
                relay_state: None,
                encrypt_then_sign: false,
                custom: None,
            },
            LoginResponseOverrides {
                acs: Some(input.acs),
                name_id_format: input.name_id_format,
                sp_provided_id: input.sp_provided_id,
                issuance_lifetime: Some(input.issuance_lifetime),
                web_browser_sso_producer: WebBrowserSsoProducer::Follow,
                status: input.status,
                typed_attributes: input.attributes,
                authn_context: input.authn_context,
                requested_authn_context: input.requested_authn_context,
            },
        )?;
        let xml = crate::binding::base64_decode(&issued.context.context)?;
        let xml = String::from_utf8(xml).map_err(|err| SamlError::Xml(err.to_string()))?;
        Ok(RenderedLoginResponse {
            id: issued.context.id,
            xml,
            session_index: issued.session_index,
        })
    }
}
