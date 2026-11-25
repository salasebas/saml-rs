//! SAML metadata parsing and shared SP/IdP metadata accessors.

pub(crate) mod description;
mod description_read;
mod endpoints;
mod entity_attributes;
mod generate;
mod idp;
mod key_certificates;
mod lifetime;
mod read;
mod role;
mod scope;
mod sp;
mod validity;
mod write;

pub use description::{ContactPerson, ContactType, LocalizedValue, Organization};
pub use entity_attributes::{EntityAttributes, SubjectIdRequirement};
pub use generate::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadataInput, SpMetadataInput,
};
pub use idp::{ArtifactResolutionServiceEndpoint, IdpMetadata};
pub use lifetime::MetadataLifetime;
pub use scope::MetadataScope;
pub use sp::SpMetadata;
pub(crate) use sp::{AcsMetadataEndpoint, DefaultMarking};
pub(crate) use validity::{MetadataValidity, RootValidUntil};

use key_certificates::KeyCertificates;
use role::{SigningFlags, SsoDescriptorRole};

use std::collections::HashSet;
use std::sync::Arc;

use crate::constants::{Binding, CertUse};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::protocol_element::SamlElement;

pub(crate) fn as_object_list(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum EndpointDirection {
    Request,
    Response,
}

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
    xml: Arc<str>,
    pub(crate) meta: Value,
    entity_id: Option<String>,
    key_certificates: KeyCertificates,
    valid_until_bounds: validity::ValidUntilBounds,
    signing_flags: SigningFlags,
    scope_elements: Vec<SamlElement>,
    description: description_read::EntityDescription,
    entity_attributes: Vec<SamlElement>,
}

impl Metadata {
    /// Parse entity metadata without selecting an SSO role, with the default
    /// XML limits and no schema validator.
    ///
    /// A root `<EntitiesDescriptor>` and its nested `<EntitiesDescriptor>` groups
    /// must contain exactly one `<EntityDescriptor>` member in the SAML metadata
    /// namespace. Content inside `<Extensions>` does not count.
    /// `KeyDescriptor` certificates and `SingleLogoutService` endpoints are
    /// read from every SSO role descriptor of the entity. A
    /// `SingleLogoutService` is read only in the SAML metadata namespace.
    /// [`SpMetadata`] and [`IdpMetadata`] read only their own role's SAML 2.0
    /// descriptors.
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
        Self::parse_role_with_policy(xml, SsoDescriptorRole::Any, policy)
            .map(|(metadata, _)| metadata)
    }

    pub(crate) fn validity(&self) -> Result<MetadataValidity, SamlError> {
        MetadataValidity::from_bounds(&self.valid_until_bounds)
    }

    /// The original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        &self.xml
    }

    /// The `entityID`. Role-specific readers apply XML Schema whitespace collapse.
    pub fn entity_id(&self) -> Option<&str> {
        self.entity_id.as_deref()
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

    /// Read the attributes that `mdattr:EntityAttributes` binds to the entity,
    /// including those of the enclosing `EntitiesDescriptor` elements,
    /// without changing the XML.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for an attribute without `Name`. Import
    /// itself does not reject entity attributes.
    pub fn entity_attributes(&self) -> Result<EntityAttributes, SamlError> {
        entity_attributes::entity_attributes(&self.entity_attributes)
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

    #[cfg(crypto)]
    pub(crate) fn encryption_key_certificates(&self) -> &[Vec<String>] {
        self.key_certificates.encryption_keys()
    }

    #[cfg(crypto)]
    pub(crate) fn role_encryption_key_certificates(&self, role: usize) -> &[Vec<String>] {
        self.key_certificates.role_encryption_keys(role)
    }

    /// First non-empty `SingleLogoutService` `Location` for `binding`, in
    /// metadata order.
    ///
    /// For the URL that receives logout responses, use
    /// [`Self::single_logout_response_location`].
    pub fn single_logout_location(&self, binding: Binding) -> Option<String> {
        self.single_logout_service_location(binding, EndpointDirection::Request)
    }

    /// First `SingleLogoutService` URL for logout responses on `binding`, in
    /// metadata order.
    ///
    /// Each endpoint for `binding` offers its non-empty `ResponseLocation`, or
    /// else its non-empty `Location`. This is the first such URL.
    pub fn single_logout_response_location(&self, binding: Binding) -> Option<String> {
        self.single_logout_service_location(binding, EndpointDirection::Response)
    }

    pub(crate) fn single_logout_service_location(
        &self,
        binding: Binding,
        direction: EndpointDirection,
    ) -> Option<String> {
        first_published_location(self.meta.get("singleLogoutService"), binding, direction)
    }

    pub(crate) fn single_logout_service_locations(
        &self,
        binding: Binding,
        direction: EndpointDirection,
    ) -> Vec<String> {
        published_locations_for_binding(self.meta.get("singleLogoutService"), binding, direction)
    }

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

    #[test]
    fn endpoints_are_read_only_in_the_metadata_namespace() -> Result<(), Box<dyn std::error::Error>>
    {
        let post = r#"Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""#;
        let soap = r#"Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP""#;
        let idp = IdpMetadata::from_xml(&format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ext="urn:example:ext" entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <ext:ArtifactResolutionService {soap} Location="https://foreign.example.com/ars" index="0"/>
    <md:ArtifactResolutionService {soap} Location="https://idp.example.com/ars" index="1"/>
    <ext:SingleLogoutService {post} Location="https://foreign.example.com/slo"/>
    <md:SingleLogoutService {post} Location="https://idp.example.com/slo"/>
    <ext:ManageNameIDService {soap} Location="https://foreign.example.com/mnid"/>
    <md:ManageNameIDService {soap} Location="https://idp.example.com/mnid"/>
    <ext:SingleSignOnService {post} Location="https://foreign.example.com/sso"/>
    <md:SingleSignOnService {post} Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        ))?;
        assert_eq!(
            idp.single_sign_on_service_locations(Binding::Post),
            vec!["https://idp.example.com/sso".to_string()]
        );
        assert_eq!(
            idp.as_metadata()
                .single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec!["https://idp.example.com/slo".to_string()]
        );
        assert_eq!(
            idp.as_metadata()
                .manage_name_id_service_locations(Binding::Soap, EndpointDirection::Request),
            vec!["https://idp.example.com/mnid".to_string()]
        );
        let artifact_resolution = idp.artifact_resolution_services()?;
        assert_eq!(
            artifact_resolution
                .iter()
                .map(|service| (service.index(), service.location()))
                .collect::<Vec<_>>(),
            vec![(1, "https://idp.example.com/ars")]
        );
        assert!(idp.artifact_resolution_service(0)?.is_none());

        let sp_xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ext="urn:example:ext" entityID="https://sp.example.com/metadata">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <ext:SingleLogoutService {post} Location="https://foreign.example.com/slo"/>
    <md:SingleLogoutService {post} Location="https://sp.example.com/slo"/>
    <ext:ManageNameIDService {soap} Location="https://foreign.example.com/mnid"/>
    <md:ManageNameIDService {soap} Location="https://sp.example.com/mnid"/>
    <ext:AssertionConsumerService {post} Location="https://foreign.example.com/acs" index="0"/>
    <md:AssertionConsumerService {post} Location="https://sp.example.com/acs" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let sp = SpMetadata::from_xml(&sp_xml)?;
        assert_eq!(
            sp.assertion_consumer_location(Binding::Post).as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert_eq!(
            sp.assertion_consumer_service_locations(Binding::Post),
            vec!["https://sp.example.com/acs".to_string()]
        );
        assert_eq!(sp.assertion_consumer_service_by_index(0)?, None);
        assert_eq!(
            sp.as_metadata()
                .single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec!["https://sp.example.com/slo".to_string()]
        );
        assert_eq!(
            sp.as_metadata()
                .manage_name_id_service_locations(Binding::Soap, EndpointDirection::Request),
            vec!["https://sp.example.com/mnid".to_string()]
        );
        assert_eq!(
            Metadata::parse(&sp_xml)?
                .single_logout_service_locations(Binding::Post, EndpointDirection::Request),
            vec!["https://sp.example.com/slo".to_string()]
        );
        Ok(())
    }
}
