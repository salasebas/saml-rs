//! Response rendering for the SOAP leg of Enhanced Client/Proxy SSO.

use super::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::constants::Binding;
use crate::entity::User;
use crate::error::SamlError;
use crate::model::Status;
use crate::sp::{ServiceProvider, WebBrowserSsoProducer};

pub(crate) struct PaosSsoResponseInput<'a> {
    pub(crate) sp: &'a ServiceProvider,
    pub(crate) acs: &'a str,
    pub(crate) in_response_to: &'a str,
    pub(crate) user: &'a User,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) issuance_lifetime: time::Duration,
    pub(crate) status: Option<&'a Status>,
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
    ) -> Result<String, SamlError> {
        let context = self.create_login_response_with_overrides(
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
                issuance_lifetime: Some(input.issuance_lifetime),
                web_browser_sso_producer: WebBrowserSsoProducer::Follow,
                status: input.status,
                typed_attributes: &[],
            },
        )?;
        let xml = crate::binding::base64_decode(&context.context)?;
        String::from_utf8(xml).map_err(|err| SamlError::Xml(err.to_string()))
    }
}
