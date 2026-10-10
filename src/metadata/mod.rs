//! SAML metadata parsing and shared SP/IdP metadata accessors.

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

use crate::constants::{Binding, CertUse};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{dom, extract_with_limits, ExtractorField, XmlLimits};

fn base_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("entityID", &["EntityDescriptor"]).attrs(&["entityID"]),
        ExtractorField::new(
            "sharedCertificate",
            &[
                "EntityDescriptor",
                "~SSODescriptor",
                "KeyDescriptor",
                "KeyInfo",
                "X509Data",
                "X509Certificate",
            ],
        ),
        ExtractorField::new(
            "certificate",
            &["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
        )
        .aggregate(&["use"], &["KeyInfo", "X509Data", "X509Certificate"]),
        ExtractorField::new(
            "singleLogoutService",
            &["EntityDescriptor", "~SSODescriptor", "SingleLogoutService"],
        )
        .attrs(&["Binding", "Location", "ResponseLocation"]),
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

fn entity_descriptor_xml<'a>(xml: &'a str, roots: &[dom::Node]) -> Result<&'a str, SamlError> {
    let [root] = roots else {
        return Ok(xml);
    };
    if root.local_name != "EntitiesDescriptor" {
        return Ok(xml);
    }
    let mut entities = Vec::new();
    collect_entity_descriptors(root, &mut entities);
    match entities.as_slice() {
        [entity] => Ok(&xml[entity.start..entity.end]),
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

pub(crate) fn location_for_binding(value: Option<&Value>, binding: Binding) -> Option<String> {
    let value = value?;
    for obj in as_object_list(value) {
        if obj.get_str("binding") == Some(binding.urn()) {
            return obj.get_str("location").map(str::to_string);
        }
    }
    None
}

/// Response endpoint for the first `binding` match.
///
/// `ResponseLocation` is that endpoint when the attribute is present and
/// non-empty. Otherwise the endpoint's `Location` is used.
pub(crate) fn response_location_for_binding(
    value: Option<&Value>,
    binding: Binding,
) -> Option<String> {
    let value = value?;
    for obj in as_object_list(value) {
        if obj.get_str("binding") != Some(binding.urn()) {
            continue;
        }
        if let Some(response_location) = non_empty_location(obj.get_str("responseLocation")) {
            return Some(response_location.to_string());
        }
        if let Some(location) = non_empty_location(obj.get_str("location")) {
            return Some(location.to_string());
        }
    }
    None
}

/// Every `Location` and `ResponseLocation` published for `binding`, in document order.
pub(crate) fn published_locations_for_binding(
    value: Option<&Value>,
    binding: Binding,
) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let mut locations = Vec::new();
    for obj in as_object_list(value) {
        if obj.get_str("binding") != Some(binding.urn()) {
            continue;
        }
        if let Some(location) = non_empty_location(obj.get_str("location")) {
            push_unique_location(&mut locations, location);
        }
        if let Some(response_location) = non_empty_location(obj.get_str("responseLocation")) {
            push_unique_location(&mut locations, response_location);
        }
    }
    locations
}

fn non_empty_location(value: Option<&str>) -> Option<&str> {
    value.filter(|location| !location.is_empty())
}

fn push_unique_location(locations: &mut Vec<String>, location: &str) {
    if locations.iter().all(|existing| existing != location) {
        locations.push(location.to_string());
    }
}

/// Parsed entity metadata (the base shared by SP and IdP).
#[derive(Debug, Clone)]
pub struct Metadata {
    xml: String,
    pub(crate) meta: Value,
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
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse_with_limits(
        xml: &str,
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
        fields.extend(extra);
        let extraction_xml = entity_descriptor_xml(xml, &roots)?;
        let mut meta = extract_with_limits(extraction_xml, &fields, limits)?;

        // A single shared certificate is used for both signing and encryption.
        if let Some(shared) = meta.get_str("sharedCertificate") {
            let shared = shared.to_string();
            meta.insert(
                "certificate",
                Value::Object(vec![
                    ("signing".into(), Value::Str(shared.clone())),
                    ("encryption".into(), Value::Str(shared)),
                ]),
            );
        }

        Ok(Self {
            xml: xml.to_string(),
            meta,
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

    /// All X.509 certificates declared for `use` (raw, as written in metadata).
    pub fn x509_certificates(&self, use_: CertUse) -> Vec<String> {
        match self
            .meta
            .get("certificate")
            .and_then(|c| c.get_key(use_.as_str()))
        {
            Some(Value::Str(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// First X.509 certificate declared for `use`.
    pub fn get_x509_certificate(&self, use_: CertUse) -> Option<String> {
        self.x509_certificates(use_).into_iter().next()
    }

    /// First `SingleLogoutService` `Location` for `binding`.
    ///
    /// Logout requests are sent to this URL. Logout responses use
    /// [`Self::get_single_logout_response_service`].
    pub fn get_single_logout_service(&self, binding: Binding) -> Option<String> {
        location_for_binding(self.meta.get("singleLogoutService"), binding)
    }

    /// `SingleLogoutService` URL where logout responses are sent for `binding`.
    ///
    /// This is `ResponseLocation` on the first endpoint for `binding` when that
    /// attribute is present. Otherwise it is that endpoint's `Location`.
    pub fn get_single_logout_response_service(&self, binding: Binding) -> Option<String> {
        response_location_for_binding(self.meta.get("singleLogoutService"), binding)
    }

    /// Every `Location` and `ResponseLocation` published on `SingleLogoutService` for `binding`.
    pub(crate) fn single_logout_service_locations(&self, binding: Binding) -> Vec<String> {
        published_locations_for_binding(self.meta.get("singleLogoutService"), binding)
    }

    /// Write the metadata XML to `path`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the filesystem write fails.
    pub fn export_metadata(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, &self.xml)
    }

    /// Bindings for which a `SingleLogoutService` endpoint is declared.
    pub fn get_support_bindings(&self) -> Vec<Binding> {
        [Binding::Redirect, Binding::Post, Binding::SimpleSign]
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
                "https://idp.example.com/sso/b".to_string(),
                "https://idp.example.com/sso/c".to_string(),
            ]
        );
        Ok(())
    }
}
