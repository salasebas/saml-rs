use crate::constants::namespace;
use crate::model::{AuthnContextReferenceKind, RequestedAuthnContext};
use crate::xml::write::XmlWriter;

#[derive(Default)]
pub(crate) struct AuthnRequestPreferences<'a> {
    pub(crate) is_passive: Option<bool>,
    pub(crate) provider_name: Option<&'a str>,
    pub(crate) requested_authn_context: Option<&'a RequestedAuthnContext>,
}

impl AuthnRequestPreferences<'_> {
    pub(super) fn validate(&self) -> Result<(), crate::error::SamlError> {
        if self
            .provider_name
            .is_some_and(|name| !name.chars().all(crate::xml::is_xml_char))
        {
            return Err(crate::error::SamlError::Invalid(
                "ProviderName must contain only XML characters".into(),
            ));
        }
        if let Some(context) = self.requested_authn_context {
            for reference in context.references() {
                reference.ensure_absolute_uri()?;
            }
        }
        Ok(())
    }
}

pub(super) struct AuthnRequestXml<'a> {
    pub(super) id: &'a str,
    pub(super) issue_instant: &'a str,
    pub(super) destination: &'a str,
    pub(super) force_authn: Option<bool>,
    pub(super) protocol_binding: Option<&'a str>,
    pub(super) assertion_consumer_service_url: Option<&'a str>,
    pub(super) assertion_consumer_service_index: Option<u16>,
    pub(super) is_passive: Option<bool>,
    pub(super) provider_name: Option<&'a str>,
    pub(super) requested_authn_context: Option<&'a RequestedAuthnContext>,
    pub(super) issuer: &'a str,
    pub(super) name_id_format: Option<&'a str>,
    pub(super) allow_create: AllowCreateAttribute,
}

pub(super) enum AllowCreateAttribute {
    Include(bool),
    Omit,
}

pub(super) fn render_default_authn_request_xml(input: &AuthnRequestXml<'_>) -> String {
    let force_authn = input.force_authn.map(|value| value.to_string());
    let is_passive = input
        .is_passive
        .map(|value| if value { "true" } else { "false" });
    let assertion_consumer_service_index = input
        .assertion_consumer_service_index
        .map(|value| value.to_string());
    let allow_create = match input.allow_create {
        AllowCreateAttribute::Include(true) => Some("true"),
        AllowCreateAttribute::Include(false) => Some("false"),
        AllowCreateAttribute::Omit => None,
    };
    let mut name_id_policy_attrs = Vec::new();
    if let Some(format) = input.name_id_format {
        name_id_policy_attrs.push(("Format", format));
    }
    if let Some(allow_create) = allow_create {
        name_id_policy_attrs.push(("AllowCreate", allow_create));
    }

    let mut attrs = Vec::with_capacity(8);
    attrs.push(("xmlns:samlp", namespace::PROTOCOL));
    attrs.push(("xmlns:saml", namespace::ASSERTION));
    attrs.push(("ID", input.id));
    attrs.push(("Version", "2.0"));
    attrs.push(("IssueInstant", input.issue_instant));
    attrs.push(("Destination", input.destination));
    if let Some(force_authn) = force_authn.as_deref() {
        attrs.push(("ForceAuthn", force_authn));
    }
    if let Some(is_passive) = is_passive {
        attrs.push(("IsPassive", is_passive));
    }
    if let Some(provider_name) = input.provider_name {
        attrs.push(("ProviderName", provider_name));
    }
    if let Some(protocol_binding) = input.protocol_binding {
        attrs.push(("ProtocolBinding", protocol_binding));
    }
    if let Some(assertion_consumer_service_url) = input.assertion_consumer_service_url {
        attrs.push((
            "AssertionConsumerServiceURL",
            assertion_consumer_service_url,
        ));
    }
    if let Some(assertion_consumer_service_index) = assertion_consumer_service_index.as_deref() {
        attrs.push((
            "AssertionConsumerServiceIndex",
            assertion_consumer_service_index,
        ));
    }

    let mut writer = XmlWriter::new();
    writer.start("samlp:AuthnRequest", &attrs);
    writer.text_element("saml:Issuer", &[], input.issuer);
    writer.empty("samlp:NameIDPolicy", &name_id_policy_attrs);
    if let Some(context) = input.requested_authn_context {
        writer.start(
            "samlp:RequestedAuthnContext",
            &[("Comparison", context.comparison().as_str())],
        );
        for reference in context.references() {
            let name = match reference.kind() {
                AuthnContextReferenceKind::Class => "saml:AuthnContextClassRef",
                AuthnContextReferenceKind::Declaration => "saml:AuthnContextDeclRef",
            };
            writer.text_element(name, &[], reference.uri());
        }
        writer.end("samlp:RequestedAuthnContext");
    }
    writer.end("samlp:AuthnRequest");
    writer.finish()
}
