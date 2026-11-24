use crate::config::validate_entity_id_syntax;
use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::model::{
    is_name_id_format, AuthnContextReferenceKind, ExtensionElement, RequestedAuthnContext,
};
use crate::xml::write::{Prefixes, XmlWriter};

#[derive(Default)]
pub(crate) struct AuthnRequestPreferences<'a> {
    pub(crate) is_passive: Option<bool>,
    pub(crate) provider_name: Option<&'a str>,
    pub(crate) sp_name_qualifier: Option<&'a str>,
    pub(crate) requested_authn_context: Option<&'a RequestedAuthnContext>,
    pub(crate) extensions: &'a [ExtensionElement],
}

impl AuthnRequestPreferences<'_> {
    pub(super) fn validate(&self, name_id_format: Option<&str>) -> Result<(), SamlError> {
        if let Some(provider_name) = self.provider_name {
            validate_provider_name(provider_name)?;
        }
        if let Some(context) = self.requested_authn_context {
            for reference in context.references() {
                reference.ensure_absolute_uri()?;
            }
        }
        if let Some(qualifier) = self.sp_name_qualifier {
            validate_entity_id_syntax(qualifier)?;
            if is_name_id_format(name_id_format, name_id_format::ENTITY) {
                return Err(SamlError::Invalid(
                    "NameIDPolicy cannot request SPNameQualifier with the entity format".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The protocol schema types `ProviderName` as `xs:string`, which allows an
/// empty name.
fn validate_provider_name(provider_name: &str) -> Result<(), SamlError> {
    if provider_name.chars().all(crate::xml::is_xml_char) {
        return Ok(());
    }
    Err(SamlError::Invalid(
        "ProviderName must contain only XML characters".into(),
    ))
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
    pub(super) extensions: &'a [ExtensionElement],
    pub(super) issuer: &'a str,
    pub(super) name_id_format: Option<&'a str>,
    pub(super) sp_name_qualifier: Option<&'a str>,
    pub(super) allow_create: bool,
}

pub(super) fn render_default_authn_request_xml(
    prefixes: Prefixes<'_>,
    input: &AuthnRequestXml<'_>,
) -> String {
    let force_authn = input.force_authn.map(|value| value.to_string());
    let is_passive = input
        .is_passive
        .map(|value| if value { "true" } else { "false" });
    let assertion_consumer_service_index = input
        .assertion_consumer_service_index
        .map(|value| value.to_string());
    let allow_create = (!is_name_id_format(input.name_id_format, name_id_format::TRANSIENT))
        .then_some(if input.allow_create { "true" } else { "false" });

    let mut name_id_policy_attrs = Vec::new();
    if let Some(format) = input.name_id_format {
        name_id_policy_attrs.push(("Format", format));
    }
    if let Some(qualifier) = input.sp_name_qualifier {
        name_id_policy_attrs.push(("SPNameQualifier", qualifier));
    }
    if let Some(allow_create) = allow_create {
        name_id_policy_attrs.push(("AllowCreate", allow_create));
    }

    let xmlns_protocol = prefixes.xmlns_protocol();
    let xmlns_assertion = prefixes.xmlns_assertion();
    let mut attrs = Vec::with_capacity(8);
    attrs.push((xmlns_protocol.as_str(), namespace::PROTOCOL));
    attrs.push((xmlns_assertion.as_str(), namespace::ASSERTION));
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
    writer.start(&prefixes.protocol("AuthnRequest"), &attrs);
    writer.text_element(&prefixes.assertion("Issuer"), &[], input.issuer);
    if !input.extensions.is_empty() {
        let name = prefixes.protocol("Extensions");
        writer.start(&name, &[]);
        for element in input.extensions {
            writer.raw(element.xml());
        }
        writer.end(&name);
    }
    writer.empty(&prefixes.protocol("NameIDPolicy"), &name_id_policy_attrs);
    if let Some(context) = input.requested_authn_context {
        writer.start(
            &prefixes.protocol("RequestedAuthnContext"),
            &[("Comparison", context.comparison().as_str())],
        );
        for reference in context.references() {
            let name = match reference.kind() {
                AuthnContextReferenceKind::Class => "AuthnContextClassRef",
                AuthnContextReferenceKind::Declaration => "AuthnContextDeclRef",
            };
            writer.text_element(&prefixes.assertion(name), &[], reference.uri());
        }
        writer.end(&prefixes.protocol("RequestedAuthnContext"));
    }
    writer.end(&prefixes.protocol("AuthnRequest"));
    writer.finish()
}
