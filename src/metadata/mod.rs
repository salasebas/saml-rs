//! SAML metadata parsing and shared SP/IdP metadata accessors.

mod endpoints;
pub mod generate;
pub mod idp;
pub mod sp;
mod write;

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use crate::crypto::MetadataSignatureVerification;
pub use generate::{
    generate_idp_metadata, generate_sp_metadata, try_generate_idp_metadata,
    ArtifactResolutionEndpoint, Endpoint, IdpMetadataConfig, SpMetadataConfig,
};
pub use idp::{ArtifactResolutionServiceEndpoint, IdpMetadata};
pub use sp::SpMetadata;

use std::collections::HashSet;

use crate::constants::{Binding, CertUse};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{dom, extract_with_limits, ExtractorField, XmlLimits};

fn base_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("entityID", &["EntityDescriptor"]).attrs(&["entityID"]),
        ExtractorField::new(
            "nameIDFormat",
            &["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
        ),
    ]
}

/// The SSO role descriptor whose `KeyDescriptor` and `SingleLogoutService`
/// elements are read.
#[derive(Clone, Copy)]
enum SsoDescriptorRole {
    Any,
    ServiceProvider,
    IdentityProvider,
}

impl SsoDescriptorRole {
    fn fields(self) -> Vec<ExtractorField> {
        let descriptor = match self {
            Self::Any => "~SSODescriptor",
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        vec![ExtractorField::new(
            "singleLogoutService",
            &["EntityDescriptor", descriptor, "SingleLogoutService"],
        )
        .with_context()]
    }

    fn is_descriptor(self, local_name: &str) -> bool {
        match self {
            Self::Any => local_name.contains("SSODescriptor"),
            Self::ServiceProvider => local_name == "SPSSODescriptor",
            Self::IdentityProvider => local_name == "IDPSSODescriptor",
        }
    }
}

/// Value of an unqualified `xs:boolean` attribute: `true`, `1`, `false`, or
/// `0`, with surrounding XML whitespace. Another lexical form is `None`.
pub(crate) fn xs_boolean(value: Option<&str>) -> Option<bool> {
    match value.map(|value| value.trim_matches([' ', '\t', '\r', '\n'])) {
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) | None => None,
    }
}

/// Normalise a "single object or array of objects" value into a node list.
pub(crate) fn as_object_list(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

/// The XML that metadata fields are extracted from, and its document element.
fn entity_descriptor_xml<'a, 'n>(
    xml: &'a str,
    roots: &'n [dom::Node],
) -> Result<(&'a str, Option<&'n dom::Node>), SamlError> {
    let [root] = roots else {
        return Ok((xml, None));
    };
    if root.local_name != "EntitiesDescriptor" {
        return Ok((xml, Some(root)));
    }
    let mut entities = Vec::new();
    collect_entity_descriptors(root, &mut entities);
    match entities.as_slice() {
        [entity] => Ok((&xml[entity.start..entity.end], Some(*entity))),
        [] => Err(SamlError::MissingMetadata("EntityDescriptor".into())),
        _ => Err(SamlError::Xml(
            "ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR".into(),
        )),
    }
}

fn collect_entity_descriptors<'a>(node: &'a dom::Node, found: &mut Vec<&'a dom::Node>) {
    if node.local_name == "EntityDescriptor" {
        found.push(node);
    }
    for child in &node.children {
        collect_entity_descriptors(child, found);
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
    fn from_entity(entity: &dom::Node, role: SsoDescriptorRole) -> Self {
        let mut certificates = Self::default();
        if entity.local_name != "EntityDescriptor" {
            return certificates;
        }
        let key_descriptors = entity
            .children
            .iter()
            .filter(|descriptor| role.is_descriptor(&descriptor.local_name))
            .flat_map(|descriptor| &descriptor.children)
            .filter(|child| child.local_name == "KeyDescriptor");
        for key_descriptor in key_descriptors {
            let x509_certificates: Vec<String> = children_named(key_descriptor, "KeyInfo")
                .flat_map(|key_info| children_named(key_info, "X509Data"))
                .flat_map(|x509_data| children_named(x509_data, "X509Certificate"))
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

fn children_named<'a>(
    node: &'a dom::Node,
    local_name: &'a str,
) -> impl Iterator<Item = &'a dom::Node> {
    node.children
        .iter()
        .filter(move |child| child.local_name == local_name)
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
}

impl Metadata {
    /// Parse `xml`, adding the role-specific `extra` extractor fields.
    ///
    /// Rejects documents carrying more than one `<EntityDescriptor>`. A root
    /// `<EntitiesDescriptor>` is accepted when it contains exactly one entity.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse(xml: &str, extra: Vec<ExtractorField>) -> Result<Self, SamlError> {
        Self::parse_with_limits(xml, extra, XmlLimits::default())
    }

    /// Parse `xml` with explicit XML parser resource limits.
    ///
    /// `KeyDescriptor` certificates and `SingleLogoutService` endpoints are
    /// read from every SSO role descriptor of the entity. [`SpMetadata`] and
    /// [`IdpMetadata`] read only their own role's.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse_with_limits(
        xml: &str,
        extra: Vec<ExtractorField>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        Self::parse_role_with_limits(xml, SsoDescriptorRole::Any, extra, limits)
    }

    fn parse_role_with_limits(
        xml: &str,
        role: SsoDescriptorRole,
        extra: Vec<ExtractorField>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let roots = dom::parse_roots_with_limits(xml, limits)?;
        if roots
            .iter()
            .filter(|n| n.local_name == "EntityDescriptor")
            .count()
            > 1
        {
            return Err(SamlError::Xml(
                "ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR".into(),
            ));
        }

        let mut fields = base_fields();
        fields.extend(role.fields());
        fields.extend(extra);
        let (extraction_xml, entity) = entity_descriptor_xml(xml, &roots)?;
        let mut meta = extract_with_limits(extraction_xml, &fields, limits)?;
        if let Some(fragments) = meta.get("singleLogoutService") {
            let endpoints = endpoints::parse_endpoint_fragments(
                fragments,
                &["Binding", "Location", "ResponseLocation"],
            )?;
            meta.insert("singleLogoutService", endpoints);
        }

        let key_certificates = entity
            .map(|entity| KeyCertificates::from_entity(entity, role))
            .unwrap_or_default();

        Ok(Self {
            xml: xml.to_string(),
            meta,
            key_certificates,
        })
    }

    /// The original metadata XML.
    pub fn get_metadata(&self) -> &str {
        &self.xml
    }

    /// `entityID`.
    pub fn get_entity_id(&self) -> Option<&str> {
        self.meta.get_str("entityID")
    }

    /// Declared `<NameIDFormat>` values.
    pub fn get_name_id_format(&self) -> Vec<String> {
        match self.meta.get("nameIDFormat") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::Str(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    /// All X.509 certificates declared for `use` (raw, as written in metadata),
    /// in document order.
    ///
    /// A `KeyDescriptor` without a `use` attribute declares its certificates
    /// for both signing and encryption.
    pub fn x509_certificates(&self, use_: CertUse) -> Vec<String> {
        self.key_certificates.for_use(use_).to_vec()
    }

    /// First X.509 certificate declared for `use`.
    pub fn get_x509_certificate(&self, use_: CertUse) -> Option<String> {
        self.x509_certificates(use_).into_iter().next()
    }

    /// First non-empty `SingleLogoutService` `Location` for `binding`.
    ///
    /// Logout requests are sent to this URL. Logout responses use
    /// [`Self::get_single_logout_response_service`].
    pub fn get_single_logout_service(&self, binding: Binding) -> Option<String> {
        first_published_location(
            self.meta.get("singleLogoutService"),
            binding,
            EndpointDirection::Request,
        )
    }

    /// `SingleLogoutService` URL where logout responses are sent for `binding`.
    ///
    /// Each endpoint for `binding` offers its non-empty `ResponseLocation`, or
    /// else its non-empty `Location`. This is the first such URL.
    pub fn get_single_logout_response_service(&self, binding: Binding) -> Option<String> {
        first_published_location(
            self.meta.get("singleLogoutService"),
            binding,
            EndpointDirection::Response,
        )
    }

    /// Every request `Location` published on `SingleLogoutService` for `binding`.
    pub(crate) fn single_logout_service_locations(&self, binding: Binding) -> Vec<String> {
        published_locations_for_binding(
            self.meta.get("singleLogoutService"),
            binding,
            EndpointDirection::Request,
        )
    }

    /// Every response location published on `SingleLogoutService` for `binding`.
    pub(crate) fn single_logout_response_service_locations(&self, binding: Binding) -> Vec<String> {
        published_locations_for_binding(
            self.meta.get("singleLogoutService"),
            binding,
            EndpointDirection::Response,
        )
    }

    /// Every `Location` published on a SOAP `ManageNameIDService` of this
    /// role, in document order.
    pub(crate) fn soap_manage_name_id_service_locations(&self) -> Vec<String> {
        self.manage_name_id_service_locations(Binding::Soap, EndpointDirection::Request)
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

    /// Write the metadata XML to `path`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the filesystem write fails.
    pub fn export_metadata(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, &self.xml)
    }

    /// Bindings for which a `SingleLogoutService` endpoint declares a
    /// non-empty `Location`.
    pub fn get_support_bindings(&self) -> Vec<Binding> {
        [
            Binding::Redirect,
            Binding::Post,
            Binding::SimpleSign,
            Binding::Soap,
        ]
        .into_iter()
        .filter(|b| self.get_single_logout_service(*b).is_some())
        .collect()
    }

    /// Verify this metadata document's enveloped signature against trusted
    /// certificate(s) (federation trust anchor). Requires a crypto provider.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, or signed `<EntityDescriptor>` coverage
    /// checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature(&self, trusted_certificates: &[String]) -> Result<bool, SamlError> {
        self.verify_signature_with_limits(trusted_certificates, XmlLimits::default())
    }

    /// Verify this metadata document's signature with explicit XML parser limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, or signed `<EntityDescriptor>` coverage
    /// checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_with_limits(
        &self,
        trusted_certificates: &[String],
        limits: XmlLimits,
    ) -> Result<bool, SamlError> {
        crate::crypto::verify_metadata_signature_with_limits(
            &self.xml,
            trusted_certificates,
            limits,
        )
    }

    /// Verify this metadata document's signature and preserve signed
    /// `<EntityDescriptor>` coverage evidence using default XML parser limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, transform policy, or signed
    /// `<EntityDescriptor>` coverage checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_detailed(
        &self,
        trusted_certificates: &[String],
    ) -> Result<crate::crypto::MetadataSignatureVerification, SamlError> {
        crate::crypto::verify_metadata_signature_detailed(&self.xml, trusted_certificates)
    }

    /// Verify this metadata document's signature and preserve signed
    /// `<EntityDescriptor>` coverage evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, transform policy, or signed
    /// `<EntityDescriptor>` coverage checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_detailed_with_limits(
        &self,
        trusted_certificates: &[String],
        limits: XmlLimits,
    ) -> Result<MetadataSignatureVerification, SamlError> {
        crate::crypto::verify_metadata_signature_detailed_with_limits(
            &self.xml,
            trusted_certificates,
            limits,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDPMETA: &str = include_str!("../../tests/fixtures/idpmeta.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/spmeta.xml");
    const MULTIPLE: &str = include_str!("../../tests/fixtures/multiple_entitydescriptor.xml");

    #[test]
    fn rejects_multiple_entity_descriptors() {
        assert!(Metadata::parse(MULTIPLE, Vec::new()).is_err());
    }

    #[test]
    fn parses_idp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdpMetadata::from_xml(IDPMETA)?;
        assert_eq!(
            idp.get_entity_id(),
            Some("https://idp.example.com/metadata")
        );
        assert!(idp.is_want_authn_requests_signed());
        assert_eq!(
            idp.get_single_sign_on_service(Binding::Redirect).as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        assert!(idp.get_x509_certificate(CertUse::Signing).is_some());
        assert!(idp
            .get_name_id_format()
            .iter()
            .any(|f| f.contains("persistent")));
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
                    idp.is_want_authn_requests_signed(),
                    sp.is_authn_request_signed(),
                    sp.is_want_assertions_signed(),
                ),
                (expected, expected, expected),
                "{value:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parses_sp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert_eq!(sp.get_entity_id(), Some("https://sp.example.org/metadata"));
        assert!(sp.is_want_assertions_signed());
        assert!(sp.is_authn_request_signed());
        assert_eq!(
            sp.get_assertion_consumer_service(Binding::Post).as_deref(),
            Some("https://sp.example.org/sp/sso")
        );
        assert_eq!(
            sp.get_single_logout_service(Binding::Redirect).as_deref(),
            Some("https://sp.example.org/sp/slo")
        );
        assert!(sp.get_x509_certificate(CertUse::Encryption).is_some());
        Ok(())
    }

    #[test]
    fn support_bindings_and_export() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert!(sp.get_support_bindings().contains(&Binding::Redirect));
        let mut path = std::env::temp_dir();
        path.push(format!("saml_rs_md_{}.xml", std::process::id()));
        sp.export_metadata(&path)?;
        assert_eq!(std::fs::read_to_string(&path)?, sp.get_metadata());
        std::fs::remove_file(&path)?;
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
        let metadata = Metadata::parse(xml, Vec::new())?;
        assert_eq!(
            metadata.get_single_logout_service(Binding::Post).as_deref(),
            Some("https://sp.example.com/slo/a")
        );
        assert_eq!(
            metadata
                .get_single_logout_response_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/slo/b")
        );
        assert_eq!(
            metadata.single_logout_service_locations(Binding::Post),
            vec![
                "https://sp.example.com/slo/a".to_string(),
                "https://sp.example.com/slo/c".to_string(),
            ]
        );
        assert_eq!(
            metadata.single_logout_response_service_locations(Binding::Post),
            vec![
                "https://sp.example.com/slo/b".to_string(),
                "https://sp.example.com/slo/c".to_string(),
            ]
        );
        assert_eq!(
            metadata
                .get_single_logout_response_service(Binding::Redirect)
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
            idp.single_logout_service_locations(Binding::Post),
            vec!["https://dual.example.com/idp/slo".to_string()]
        );
        assert_eq!(
            idp.single_logout_response_service_locations(Binding::Post),
            vec!["https://dual.example.com/idp/slo/response".to_string()]
        );
        assert_eq!(idp.get_support_bindings(), vec![Binding::Post]);

        let sp = SpMetadata::from_xml(xml)?;
        assert_eq!(
            sp.get_single_logout_service(Binding::Post).as_deref(),
            Some("https://dual.example.com/sp/slo")
        );
        assert_eq!(
            sp.get_single_logout_response_service(Binding::Post)
                .as_deref(),
            Some("https://dual.example.com/sp/slo/response")
        );
        assert_eq!(
            sp.single_logout_service_locations(Binding::Post),
            vec!["https://dual.example.com/sp/slo".to_string()]
        );
        assert_eq!(
            sp.get_support_bindings(),
            vec![Binding::Redirect, Binding::Post]
        );

        let any_role = Metadata::parse(xml, Vec::new())?;
        assert_eq!(
            any_role.single_logout_service_locations(Binding::Post),
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
            encryption_only.x509_certificates(CertUse::Signing),
            Vec::<String>::new()
        );
        assert_eq!(
            encryption_only.x509_certificates(CertUse::Encryption),
            vec!["ENCRYPTION".to_string()]
        );

        let signing_only = IdpMetadata::from_xml(&idp_metadata_with_keys(&key_descriptor(
            r#" use="signing""#,
            "SIGNING",
        )))?;
        assert_eq!(
            signing_only.x509_certificates(CertUse::Signing),
            vec!["SIGNING".to_string()]
        );
        assert_eq!(
            signing_only.x509_certificates(CertUse::Encryption),
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
            idp.x509_certificates(CertUse::Signing),
            vec!["OLD".to_string(), "NEW".to_string()]
        );
        assert_eq!(
            idp.x509_certificates(CertUse::Encryption),
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
        assert_eq!(idp.x509_certificates(CertUse::Signing), vec!["IDP-SIGNING"]);
        assert_eq!(
            idp.x509_certificates(CertUse::Encryption),
            vec!["IDP-ENCRYPTION"]
        );

        let sp = SpMetadata::from_xml(xml)?;
        assert_eq!(sp.x509_certificates(CertUse::Signing), vec!["SP-SHARED"]);
        assert_eq!(sp.x509_certificates(CertUse::Encryption), vec!["SP-SHARED"]);

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
            idp.get_single_sign_on_service(Binding::Post).as_deref(),
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
            idp.get_single_sign_on_service(Binding::Post).as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert_eq!(
            idp.single_sign_on_service_locations(Binding::Post),
            vec!["https://idp.example.com/sso".to_string()]
        );
        assert_eq!(idp.get_single_sign_on_service(Binding::Redirect), None);
        assert_eq!(
            idp.get_single_logout_service(Binding::Post).as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(
            idp.get_single_logout_response_service(Binding::Post)
                .as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(idp.get_single_logout_service(Binding::Redirect), None);
        assert_eq!(idp.get_support_bindings(), vec![Binding::Post]);
        Ok(())
    }
}
