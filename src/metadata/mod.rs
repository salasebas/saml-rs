//! SAML metadata parsing and shared SP/IdP metadata accessors.

pub(crate) mod description;
mod description_read;
mod endpoints;
mod generate;
mod idp;
mod lifetime;
mod role;
mod sp;
mod validity;
mod write;

pub use description::{ContactPerson, ContactType, LocalizedValue, Organization};
pub use generate::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadataInput, SpMetadataInput,
};
pub use idp::{ArtifactResolutionServiceEndpoint, IdpMetadata};
pub use lifetime::MetadataLifetime;
pub use sp::SpMetadata;
pub(crate) use validity::MetadataValidity;

use role::{SigningFlags, SsoDescriptorRole};

use std::collections::HashSet;
use std::ops::Range;

use crate::constants::{namespace, Binding, CertUse};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{dom, extract_with_limits, ExtractorField};

const MULTIPLE_ENTITY_DESCRIPTORS: &str = "metadata has more than one EntityDescriptor";

fn base_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("entityID", &["EntityDescriptor"]).attrs(&["entityID"]),
        ExtractorField::new(
            "nameIDFormat",
            &["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
        ),
    ]
}

/// Normalise a "single object or array of objects" value into a node list.
pub(crate) fn as_object_list(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

/// The range of `xml` that metadata fields are extracted from, and the
/// `EntityDescriptor` it holds.
fn entity_descriptor_xml<'n>(
    xml: &str,
    roots: &'n [dom::Node],
    descriptor_starts: &HashSet<usize>,
) -> Result<(Range<usize>, Option<&'n dom::Node>), SamlError> {
    let [root] = roots else {
        return Ok((0..xml.len(), None));
    };
    if root.local_name != "EntitiesDescriptor" {
        return Ok((
            0..xml.len(),
            Some(root).filter(|root| root.local_name == "EntityDescriptor"),
        ));
    }
    let mut entities = Vec::new();
    collect_entity_descriptors(root, descriptor_starts, &mut entities);
    match entities.as_slice() {
        [entity] => Ok((entity.start..entity.end, Some(*entity))),
        [] => Err(SamlError::MissingMetadata("EntityDescriptor".into())),
        _ => Err(SamlError::xml(MULTIPLE_ENTITY_DESCRIPTORS)),
    }
}

fn role_xml(
    xml: &str,
    extraction: Range<usize>,
    entity: Option<&dom::Node>,
    descriptors: &[&dom::Node],
) -> String {
    let mut role_xml = String::with_capacity(extraction.len());
    let mut copied = extraction.start;
    let children = entity
        .map(|entity| entity.children.as_slice())
        .unwrap_or_default();
    for unread in children.iter().filter(|child| {
        role::is_sso_descriptor(child)
            && !descriptors
                .iter()
                .any(|descriptor| std::ptr::eq(*descriptor, *child))
    }) {
        role_xml.push_str(&xml[copied..unread.start]);
        copied = unread.end;
    }
    role_xml.push_str(&xml[copied..extraction.end]);
    role_xml
}

fn collect_entity_descriptors<'a>(
    node: &'a dom::Node,
    descriptor_starts: &HashSet<usize>,
    found: &mut Vec<&'a dom::Node>,
) {
    if !descriptor_starts.contains(&node.start) {
        return;
    }
    if node.local_name == "EntityDescriptor" {
        found.push(node);
    } else {
        for child in &node.children {
            collect_entity_descriptors(child, descriptor_starts, found);
        }
    }
}

/// X.509 certificates published by the `KeyDescriptor`s of the parsed SSO
/// role descriptors, in document order.
///
/// A `KeyDescriptor` without `use` serves both signing and encryption.
#[derive(Debug, Clone, Default)]
struct KeyCertificates {
    signing: Vec<String>,
    encryption: Vec<String>,
}

impl KeyCertificates {
    fn from_descriptors(descriptors: &[&dom::Node]) -> Self {
        let mut certificates = Self::default();
        let key_descriptors = descriptors
            .iter()
            .flat_map(|descriptor| &descriptor.children)
            .filter(|child| child.local_name == "KeyDescriptor");
        for key_descriptor in key_descriptors {
            let x509_certificates: Vec<String> = key_descriptor
                .children_named("KeyInfo")
                .flat_map(|key_info| key_info.children_named("X509Data"))
                .flat_map(|x509_data| x509_data.children_named("X509Certificate"))
                .map(|certificate| certificate.text.clone())
                .collect();
            match key_descriptor.attr("use") {
                None => {
                    certificates
                        .signing
                        .extend(x509_certificates.iter().cloned());
                    certificates.encryption.extend(x509_certificates);
                }
                Some(use_) if use_ == CertUse::Signing.as_str() => {
                    certificates.signing.extend(x509_certificates);
                }
                Some(use_) if use_ == CertUse::Encryption.as_str() => {
                    certificates.encryption.extend(x509_certificates);
                }
                Some(_) => {}
            }
        }
        certificates
    }

    fn for_use(&self, use_: CertUse) -> &[String] {
        match use_ {
            CertUse::Signing => &self.signing,
            CertUse::Encryption => &self.encryption,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum EndpointDirection {
    Request,
    Response,
}

/// Non-empty locations for the binding and message direction, in document
/// order, including repeats.
fn published_locations(
    value: Option<&Value>,
    binding: Binding,
    direction: EndpointDirection,
) -> impl Iterator<Item = &str> {
    value
        .into_iter()
        .flat_map(as_object_list)
        .filter(move |obj| obj.get_str("binding") == Some(binding.urn()))
        .filter_map(move |obj| match direction {
            EndpointDirection::Request => non_empty_location(obj.get_str("location")),
            EndpointDirection::Response => non_empty_location(obj.get_str("responseLocation"))
                .or_else(|| non_empty_location(obj.get_str("location"))),
        })
}

/// Published locations for the binding and message direction, in document order.
pub(crate) fn published_locations_for_binding(
    value: Option<&Value>,
    binding: Binding,
    direction: EndpointDirection,
) -> Vec<String> {
    let mut seen = HashSet::new();
    published_locations(value, binding, direction)
        .filter(|location| seen.insert(*location))
        .map(str::to_string)
        .collect()
}

/// First published location for the binding and message direction.
pub(crate) fn first_published_location(
    value: Option<&Value>,
    binding: Binding,
    direction: EndpointDirection,
) -> Option<String> {
    published_locations(value, binding, direction)
        .next()
        .map(str::to_string)
}

fn non_empty_location(value: Option<&str>) -> Option<&str> {
    value.filter(|location| !location.is_empty())
}

/// Parsed entity metadata (the base shared by SP and IdP).
#[derive(Debug, Clone)]
pub struct Metadata {
    xml: String,
    pub(crate) meta: Value,
    key_certificates: KeyCertificates,
    valid_until_bounds: Vec<String>,
    signing_flags: SigningFlags,
    description: description_read::EntityDescription,
}

impl Metadata {
    /// Parse entity metadata without selecting an SSO role, with the default
    /// XML limits and no schema validator.
    ///
    /// A root `<EntitiesDescriptor>` and its nested `<EntitiesDescriptor>` groups
    /// must contain exactly one `<EntityDescriptor>` member in the SAML metadata
    /// namespace. Content inside `<Extensions>` does not count.
    /// `KeyDescriptor` certificates and `SingleLogoutService` endpoints are
    /// read from every SSO role descriptor of the entity. [`SpMetadata`] and
    /// [`IdpMetadata`] read only their own role's SAML 2.0 descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse(xml: &str) -> Result<Self, SamlError> {
        Self::parse_with_policy(xml, &crate::XmlPolicy::default())
    }

    /// Parse metadata as [`Self::parse`] does, with the XML limits and
    /// optional schema validator of `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits, schema
    /// validation, extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse_with_policy(xml: &str, policy: &crate::XmlPolicy) -> Result<Self, SamlError> {
        Self::parse_role_with_policy(xml, SsoDescriptorRole::Any, Vec::new(), policy)
    }

    fn parse_role_with_policy(
        xml: &str,
        role: SsoDescriptorRole,
        extra: Vec<ExtractorField>,
        policy: &crate::XmlPolicy,
    ) -> Result<Self, SamlError> {
        let limits = policy.limits;
        let mut descriptor_starts = HashSet::new();
        let roots = dom::parse_roots_with_element_names(xml, limits, |start, ns, name| {
            if ns == Some(namespace::METADATA)
                && matches!(name, "EntitiesDescriptor" | "EntityDescriptor")
            {
                descriptor_starts.insert(start);
            }
        })?;
        crate::schema::validate(xml, policy.schema_validator)?;
        if roots
            .iter()
            .filter(|n| n.local_name == "EntityDescriptor")
            .count()
            > 1
        {
            return Err(SamlError::xml(MULTIPLE_ENTITY_DESCRIPTORS));
        }

        let (extraction, entity) = entity_descriptor_xml(xml, &roots, &descriptor_starts)?;
        let descriptors = role.descriptors(xml, entity, limits)?;

        let mut fields = base_fields();
        fields.extend(role.fields());
        fields.extend(extra);
        let mut meta = extract_with_limits(
            &role_xml(xml, extraction, entity, &descriptors.nodes),
            &fields,
            limits,
        )?;
        endpoints::read_endpoints(
            &mut meta,
            "singleLogoutService",
            &["Binding", "Location", "ResponseLocation"],
        )?;

        Ok(Self {
            xml: xml.to_string(),
            meta,
            key_certificates: KeyCertificates::from_descriptors(&descriptors.nodes),
            valid_until_bounds: descriptors.valid_until_bounds,
            signing_flags: descriptors.signing_flags,
            description: description_read::EntityDescription::read(xml, entity, limits)?,
        })
    }

    pub(crate) fn validity(&self) -> Result<MetadataValidity, SamlError> {
        MetadataValidity::from_bounds(&self.valid_until_bounds)
    }

    /// The original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        &self.xml
    }

    /// `entityID`.
    pub fn entity_id(&self) -> Option<&str> {
        self.meta.get_str("entityID")
    }

    /// Read the entity-level organization without changing the imported XML.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for multiple organizations or a localized
    /// value without `xml:lang`. Import itself does not reject these descriptions.
    pub fn organization(&self) -> Result<Option<Organization>, SamlError> {
        self.description.organization()
    }

    /// Read entity-level contacts in document order without changing the XML.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for a missing or unknown `contactType`.
    /// Import itself does not reject these descriptions.
    pub fn contacts(&self) -> Result<Vec<ContactPerson>, SamlError> {
        self.description.contacts()
    }

    /// `<NameIDFormat>` values of the SSO role descriptors read, in document
    /// order, after XML Schema whitespace collapse.
    pub fn name_id_formats(&self) -> Vec<crate::NameIdFormat> {
        let values = match self.meta.get("nameIDFormat") {
            Some(Value::Array(items)) => items.as_slice(),
            Some(value @ Value::Str(_)) => std::slice::from_ref(value),
            Some(Value::Null | Value::Object(_)) | None => &[],
        };
        values
            .iter()
            .filter_map(Value::as_str)
            .map(|value| {
                crate::NameIdFormat::from_uri(&crate::xml::any_uri::collapse_whitespace(value))
            })
            .collect()
    }

    /// All X.509 certificates declared for `use` (raw, as written in metadata),
    /// in document order.
    ///
    /// A `KeyDescriptor` without a `use` attribute declares its certificates
    /// for both signing and encryption.
    pub fn x509_certificates(&self, use_: CertUse) -> &[String] {
        self.key_certificates.for_use(use_)
    }

    /// First non-empty `SingleLogoutService` `Location` for `binding`.
    ///
    /// Logout requests are sent to this URL. Logout responses use
    /// [`Self::single_logout_response_location`].
    pub fn single_logout_location(&self, binding: Binding) -> Option<String> {
        self.single_logout_service_location(binding, EndpointDirection::Request)
    }

    /// `SingleLogoutService` URL where logout responses are sent for `binding`.
    ///
    /// Each endpoint for `binding` offers its non-empty `ResponseLocation`, or
    /// else its non-empty `Location`. This is the first such URL.
    pub fn single_logout_response_location(&self, binding: Binding) -> Option<String> {
        self.single_logout_service_location(binding, EndpointDirection::Response)
    }

    /// First location published on `SingleLogoutService` for `binding` and
    /// message direction.
    pub(crate) fn single_logout_service_location(
        &self,
        binding: Binding,
        direction: EndpointDirection,
    ) -> Option<String> {
        first_published_location(self.meta.get("singleLogoutService"), binding, direction)
    }

    /// Every location published on `SingleLogoutService` for `binding` and
    /// message direction, in document order.
    pub(crate) fn single_logout_service_locations(
        &self,
        binding: Binding,
        direction: EndpointDirection,
    ) -> Vec<String> {
        published_locations_for_binding(self.meta.get("singleLogoutService"), binding, direction)
    }

    /// Every location published on a `ManageNameIDService` of this role for
    /// `binding` and message direction, in document order.
    pub(crate) fn manage_name_id_service_locations(
        &self,
        binding: Binding,
        direction: EndpointDirection,
    ) -> Vec<String> {
        published_locations_for_binding(self.meta.get("manageNameIDService"), binding, direction)
    }

    /// Bindings for which a `SingleLogoutService` endpoint declares a
    /// non-empty `Location`.
    pub fn single_logout_bindings(&self) -> Vec<Binding> {
        [
            Binding::Redirect,
            Binding::Post,
            Binding::SimpleSign,
            Binding::Soap,
        ]
        .into_iter()
        .filter(|b| self.single_logout_location(*b).is_some())
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDPMETA: &str = include_str!("../../tests/fixtures/misc/idpmeta.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/misc/spmeta.xml");
    const MULTIPLE: &str = include_str!("../../tests/fixtures/misc/multiple_entitydescriptor.xml");

    #[test]
    fn rejects_multiple_entity_descriptors() {
        assert!(Metadata::parse(MULTIPLE).is_err());
    }

    #[test]
    fn rejects_content_outside_the_document_element() {
        let entity = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://dual.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/idp/sso"/></IDPSSODescriptor><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/sp/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#;
        for xml in [
            format!("{entity}junk"),
            format!("junk{entity}"),
            format!("{entity}<![CDATA[x]]>"),
            format!("{entity}&amp;"),
            format!("{entity}<Extra/>"),
            format!("<Extra/>{entity}"),
        ] {
            assert!(
                matches!(Metadata::parse(&xml), Err(SamlError::Xml { .. })),
                "{xml}"
            );
            assert!(
                matches!(IdpMetadata::from_xml(&xml), Err(SamlError::Xml { .. })),
                "{xml}"
            );
            assert!(
                matches!(SpMetadata::from_xml(&xml), Err(SamlError::Xml { .. })),
                "{xml}"
            );
        }
    }

    #[test]
    fn reads_extra_fields_under_a_root_that_is_not_an_entity() -> Result<(), SamlError> {
        let xml = r#"<Foo><SPSSODescriptor><X a="1"/></SPSSODescriptor></Foo>"#;
        let field = ExtractorField::new("x", &["Foo", "SPSSODescriptor", "X"]).attrs(&["a"]);
        let metadata = Metadata::parse_role_with_policy(
            xml,
            SsoDescriptorRole::Any,
            vec![field],
            &crate::XmlPolicy::default(),
        )?;
        assert_eq!(metadata.meta.get_str("x"), Some("1"));
        Ok(())
    }

    #[test]
    fn parses_idp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdpMetadata::from_xml(IDPMETA)?;
        assert_eq!(
            idp.as_metadata().entity_id(),
            Some("https://idp.example.com/metadata")
        );
        assert!(idp.want_authn_requests_signed());
        assert_eq!(
            idp.single_sign_on_location(Binding::Redirect).as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        assert!(!idp
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .is_empty());
        assert!(idp
            .as_metadata()
            .name_id_formats()
            .contains(&crate::NameIdFormat::Persistent));
        Ok(())
    }

    #[test]
    fn signing_flags_read_every_xs_boolean_lexical_form() -> Result<(), Box<dyn std::error::Error>>
    {
        for (value, expected) in [
            ("true", true),
            ("1", true),
            (" 1\n", true),
            ("false", false),
            ("0", false),
        ] {
            let xml = format!(
                r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://dual.example.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="{value}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/idp/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor AuthnRequestsSigned="{value}" WantAssertionsSigned="{value}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/sp/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
            );
            let idp = IdpMetadata::from_xml(&xml)?;
            let sp = SpMetadata::from_xml(&xml)?;
            assert_eq!(
                (
                    idp.want_authn_requests_signed(),
                    sp.authn_requests_signed(),
                    sp.want_assertions_signed(),
                ),
                (expected, expected, expected),
                "{value:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn authn_requests_signed_is_read_from_every_saml2_sp_role(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (second, expected) in [("AuthnRequestsSigned=\"true\"", true), ("", false)] {
            let xml = format!(
                r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
  <SPSSODescriptor {second} protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs2" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
            );
            assert_eq!(
                SpMetadata::from_xml(&xml)?.authn_requests_signed(),
                expected,
                "{second:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parses_sp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert_eq!(
            sp.as_metadata().entity_id(),
            Some("https://sp.example.org/metadata")
        );
        assert!(sp.want_assertions_signed());
        assert!(sp.authn_requests_signed());
        assert_eq!(
            sp.assertion_consumer_location(Binding::Post).as_deref(),
            Some("https://sp.example.org/sp/sso")
        );
        assert_eq!(
            sp.as_metadata()
                .single_logout_location(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.org/sp/slo")
        );
        assert!(!sp
            .as_metadata()
            .x509_certificates(CertUse::Encryption)
            .is_empty());
        Ok(())
    }

    #[test]
    fn single_logout_reads_response_location_and_every_published_location(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo/a" ResponseLocation="https://sp.example.com/slo/b"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo/c" ResponseLocation=""/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo/a" ResponseLocation="https://sp.example.com/slo/c"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/slo/redirect"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;
        let metadata = Metadata::parse(xml)?;
        assert_eq!(
            metadata.single_logout_location(Binding::Post).as_deref(),
            Some("https://sp.example.com/slo/a")
        );
        assert_eq!(
            metadata
                .single_logout_response_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/slo/b")
        );
        assert_eq!(
            metadata.single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec![
                "https://sp.example.com/slo/a".to_string(),
                "https://sp.example.com/slo/c".to_string(),
            ]
        );
        assert_eq!(
            metadata.single_logout_service_locations(Binding::Post, EndpointDirection::Response),
            vec![
                "https://sp.example.com/slo/b".to_string(),
                "https://sp.example.com/slo/c".to_string(),
            ]
        );
        assert_eq!(
            metadata
                .single_logout_response_location(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.com/slo/redirect")
        );
        Ok(())
    }

    #[test]
    fn single_logout_service_comes_from_the_parsed_role() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://dual.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/idp/slo" ResponseLocation="https://dual.example.com/idp/slo/response"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/idp/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/sp/slo" ResponseLocation="https://dual.example.com/sp/slo/response"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dual.example.com/sp/slo/redirect"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/sp/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;
        let idp = IdpMetadata::from_xml(xml)?;
        assert_eq!(
            idp.as_metadata()
                .single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec!["https://dual.example.com/idp/slo".to_string()]
        );
        assert_eq!(
            idp.as_metadata()
                .single_logout_service_locations(Binding::Post, EndpointDirection::Response),
            vec!["https://dual.example.com/idp/slo/response".to_string()]
        );
        assert_eq!(
            idp.as_metadata().single_logout_bindings(),
            vec![Binding::Post]
        );

        let sp = SpMetadata::from_xml(xml)?;
        assert_eq!(
            sp.as_metadata()
                .single_logout_location(Binding::Post)
                .as_deref(),
            Some("https://dual.example.com/sp/slo")
        );
        assert_eq!(
            sp.as_metadata()
                .single_logout_response_location(Binding::Post)
                .as_deref(),
            Some("https://dual.example.com/sp/slo/response")
        );
        assert_eq!(
            sp.as_metadata()
                .single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec!["https://dual.example.com/sp/slo".to_string()]
        );
        assert_eq!(
            sp.as_metadata().single_logout_bindings(),
            vec![Binding::Redirect, Binding::Post]
        );

        let any_role = Metadata::parse(xml)?;
        assert_eq!(
            any_role.single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec![
                "https://dual.example.com/idp/slo".to_string(),
                "https://dual.example.com/sp/slo".to_string(),
            ]
        );
        Ok(())
    }

    fn idp_metadata_with_keys(key_descriptors: &str) -> String {
        format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptors}
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#
        )
    }

    fn key_descriptor(use_attribute: &str, certificate: &str) -> String {
        format!(
            "<KeyDescriptor{use_attribute}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"
        )
    }

    #[test]
    fn a_key_with_one_use_serves_only_that_use() -> Result<(), Box<dyn std::error::Error>> {
        let encryption_only = IdpMetadata::from_xml(&idp_metadata_with_keys(&key_descriptor(
            r#" use="encryption""#,
            "ENCRYPTION",
        )))?;
        assert_eq!(
            encryption_only
                .as_metadata()
                .x509_certificates(CertUse::Signing),
            Vec::<String>::new()
        );
        assert_eq!(
            encryption_only
                .as_metadata()
                .x509_certificates(CertUse::Encryption),
            vec!["ENCRYPTION".to_string()]
        );

        let signing_only = IdpMetadata::from_xml(&idp_metadata_with_keys(&key_descriptor(
            r#" use="signing""#,
            "SIGNING",
        )))?;
        assert_eq!(
            signing_only
                .as_metadata()
                .x509_certificates(CertUse::Signing),
            vec!["SIGNING".to_string()]
        );
        assert_eq!(
            signing_only
                .as_metadata()
                .x509_certificates(CertUse::Encryption),
            Vec::<String>::new()
        );
        Ok(())
    }

    #[test]
    fn a_key_without_use_serves_signing_and_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let key_descriptors = [
            key_descriptor(r#" use="signing""#, "OLD"),
            key_descriptor("", "NEW"),
            key_descriptor(r#" use="encryption""#, "ENCRYPTION"),
        ]
        .concat();
        let idp = IdpMetadata::from_xml(&idp_metadata_with_keys(&key_descriptors))?;
        assert_eq!(
            idp.as_metadata().x509_certificates(CertUse::Signing),
            vec!["OLD".to_string(), "NEW".to_string()]
        );
        assert_eq!(
            idp.as_metadata().x509_certificates(CertUse::Encryption),
            vec!["NEW".to_string(), "ENCRYPTION".to_string()]
        );
        Ok(())
    }

    #[test]
    fn key_descriptors_come_from_the_parsed_role() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://dual.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>IDP-SIGNING</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>IDP-ENCRYPTION</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/idp/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>SP-SHARED</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dual.example.com/sp/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;
        let idp = IdpMetadata::from_xml(xml)?;
        assert_eq!(
            idp.as_metadata().x509_certificates(CertUse::Signing),
            vec!["IDP-SIGNING"]
        );
        assert_eq!(
            idp.as_metadata().x509_certificates(CertUse::Encryption),
            vec!["IDP-ENCRYPTION"]
        );

        let sp = SpMetadata::from_xml(xml)?;
        assert_eq!(
            sp.as_metadata().x509_certificates(CertUse::Signing),
            vec!["SP-SHARED"]
        );
        assert_eq!(
            sp.as_metadata().x509_certificates(CertUse::Encryption),
            vec!["SP-SHARED"]
        );

        Ok(())
    }

    #[test]
    fn single_sign_on_keeps_every_location_for_one_binding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/a" ResponseLocation="https://idp.example.com/sso/b"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/c"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let idp = IdpMetadata::from_xml(xml)?;
        assert_eq!(
            idp.single_sign_on_location(Binding::Post).as_deref(),
            Some("https://idp.example.com/sso/a")
        );
        assert_eq!(
            idp.single_sign_on_service_locations(Binding::Post),
            vec![
                "https://idp.example.com/sso/a".to_string(),
                "https://idp.example.com/sso/c".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn endpoints_without_a_location_are_skipped_by_every_accessor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location=""/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/slo"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location=""/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location=""/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location=""/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let idp = IdpMetadata::from_xml(xml)?;
        assert_eq!(
            idp.single_sign_on_location(Binding::Post).as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert_eq!(
            idp.single_sign_on_service_locations(Binding::Post),
            vec!["https://idp.example.com/sso".to_string()]
        );
        assert_eq!(idp.single_sign_on_location(Binding::Redirect), None);
        assert_eq!(
            idp.as_metadata()
                .single_logout_location(Binding::Post)
                .as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(
            idp.as_metadata()
                .single_logout_response_location(Binding::Post)
                .as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(
            idp.as_metadata().single_logout_location(Binding::Redirect),
            None
        );
        assert_eq!(
            idp.as_metadata().single_logout_bindings(),
            vec![Binding::Post]
        );
        Ok(())
    }

    #[test]
    fn every_endpoint_collapses_binding_and_location_whitespace(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let post = r#"Binding=" urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
 ""#;
        let redirect = r#"Binding=" urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect ""#;
        let soap = r#"Binding=" urn:oasis:names:tc:SAML:2.0:bindings:SOAP ""#;
        let idp = IdpMetadata::from_xml(&format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <ArtifactResolutionService {soap} Location=" https://idp.example.com/ars " index=" 0 "/>
    <SingleLogoutService {post} Location=" https://idp.example.com/slo "/>
    <ManageNameIDService {redirect} Location=" https://idp.example.com/mnid " ResponseLocation=" https://idp.example.com/mnid/response "/>
    <SingleSignOnService {post} Location=" https://idp.example.com/sso "/>
  </IDPSSODescriptor>
</EntityDescriptor>"#
        ))?;
        assert_eq!(
            idp.as_metadata()
                .single_logout_location(Binding::Post)
                .as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(
            idp.single_sign_on_location(Binding::Post).as_deref(),
            Some("https://idp.example.com/sso")
        );
        let artifact_resolution = idp.artifact_resolution_services()?;
        assert_eq!(artifact_resolution.len(), 1);
        assert_eq!(artifact_resolution[0].index(), 0);
        assert!(artifact_resolution[0].is_soap());
        assert_eq!(
            artifact_resolution[0].location(),
            "https://idp.example.com/ars"
        );
        assert_eq!(
            idp.as_metadata()
                .manage_name_id_service_locations(Binding::Redirect, EndpointDirection::Response),
            vec!["https://idp.example.com/mnid/response".to_string()]
        );

        let sp = SpMetadata::from_xml(&format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService {post} Location=" https://sp.example.com/slo "/>
    <ManageNameIDService {redirect} Location=" https://sp.example.com/mnid "/>
    <AssertionConsumerService {post} Location=" https://sp.example.com/acs " index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
        ))?;
        assert_eq!(
            sp.as_metadata()
                .single_logout_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/slo")
        );
        assert_eq!(
            sp.assertion_consumer_location(Binding::Post).as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert_eq!(
            sp.as_metadata()
                .manage_name_id_service_locations(Binding::Redirect, EndpointDirection::Request),
            vec!["https://sp.example.com/mnid".to_string()]
        );
        Ok(())
    }
}
