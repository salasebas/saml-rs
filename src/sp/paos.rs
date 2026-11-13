//! AuthnRequest rendering for the PAOS leg of Enhanced Client/Proxy SSO.

use super::{
    render_default_authn_request_xml, AllowCreateAttribute, AuthnRequestXml, ServiceProvider,
};
use crate::constants::Binding;
use crate::entity::{generate_id, now_iso8601};
use crate::error::SamlError;
use crate::model::validate_name_id_format;

pub(crate) struct PaosAuthnRequestInput<'a> {
    pub(crate) destination: &'a str,
    pub(crate) assertion_consumer_service_url: &'a str,
    pub(crate) force_authn: Option<bool>,
    pub(crate) is_passive: Option<bool>,
    pub(crate) sign: bool,
}

impl ServiceProvider {
    /// AuthnRequest ID and XML for the PAOS leg of Enhanced Client/Proxy SSO.
    ///
    /// `ProtocolBinding` stays omitted. The assertion consumer URL is carried
    /// on the request and on the PAOS header. When `sign` is set, the request
    /// receives the same enveloped signature HTTP-POST uses.
    pub(crate) fn render_paos_authn_request(
        &self,
        input: &PaosAuthnRequestInput<'_>,
    ) -> Result<(String, String), SamlError> {
        let name_id_format = self.setting.default_name_id_format();
        validate_name_id_format(name_id_format)?;
        let allow_create = if name_id_format == Some(crate::constants::name_id_format::TRANSIENT) {
            AllowCreateAttribute::Omit
        } else {
            AllowCreateAttribute::Include(self.setting.allow_create)
        };
        let id = generate_id();
        let issue_instant = now_iso8601();
        let issuer = self.entity_id();
        let xml = render_default_authn_request_xml(&AuthnRequestXml {
            id: &id,
            issue_instant: &issue_instant,
            destination: input.destination,
            force_authn: input.force_authn,
            protocol_binding: None,
            assertion_consumer_service_url: Some(input.assertion_consumer_service_url),
            assertion_consumer_service_index: None,
            is_passive: input.is_passive,
            provider_name: None,
            requested_authn_context: None,
            issuer: &issuer,
            name_id_format,
            allow_create,
        });
        if !input.sign {
            return Ok((id, xml));
        }
        let signed = self.signed_request_context(
            Binding::Post,
            &xml,
            input.destination.to_string(),
            None,
            id,
        )?;
        let xml = crate::binding::base64_decode(&signed.context)?;
        let xml = String::from_utf8(xml).map_err(|err| SamlError::Xml(err.to_string()))?;
        Ok((signed.id, xml))
    }
}
