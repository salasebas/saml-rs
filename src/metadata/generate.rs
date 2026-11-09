//! SAML SP and IdP metadata generation.

use crate::constants::{elements_order, name_id_format, namespace, Binding};
use crate::error::SamlError;
use crate::metadata::write::MetadataWriter;
use crate::util::{is_non_empty_array, normalize_cert_string};

/// Indexed `ArtifactResolutionService` location. The binding is SOAP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactResolutionEndpoint {
    /// `index` selecting this endpoint from an artifact.
    pub index: u16,
    /// Endpoint URL.
    pub location: String,
}

/// A protocol endpoint (`SingleSignOnService` / `SingleLogoutService` / ACS).
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Protocol binding.
    pub binding: Binding,
    /// Endpoint URL.
    pub location: String,
    /// ACS index for `AssertionConsumerService`; ignored for other endpoint kinds.
    pub index: Option<u16>,
    /// Whether this is the default endpoint.
    pub is_default: bool,
}

impl Endpoint {
    /// Convenience constructor (non-default).
    pub fn new(binding: Binding, location: impl Into<String>) -> Self {
        Self {
            binding,
            location: location.into(),
            index: None,
            is_default: false,
        }
    }
}

/// SP metadata generation input.
#[derive(Debug, Clone, Default)]
pub struct SpMetadataConfig {
    /// `entityID`.
    pub entity_id: String,
    /// Signing certificates (PEM or bare base64).
    pub signing_certs: Vec<String>,
    /// Encryption certificates (PEM or bare base64).
    pub encrypt_certs: Vec<String>,
    /// `AuthnRequestsSigned`.
    pub authn_requests_signed: bool,
    /// `WantAssertionsSigned`.
    pub want_assertions_signed: bool,
    /// `<NameIDFormat>` values (defaults to email address when empty).
    pub name_id_format: Vec<String>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// `AssertionConsumerService` endpoints.
    pub assertion_consumer_service: Vec<Endpoint>,
    /// Element ordering profile (defaults to [`elements_order::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
}

/// IdP metadata generation input.
#[derive(Debug, Clone, Default)]
pub struct IdpMetadataConfig {
    /// `entityID`.
    pub entity_id: String,
    /// Signing certificates.
    pub signing_certs: Vec<String>,
    /// Encryption certificates.
    pub encrypt_certs: Vec<String>,
    /// `WantAuthnRequestsSigned`.
    pub want_authn_requests_signed: bool,
    /// `<NameIDFormat>` values.
    pub name_id_format: Vec<String>,
    /// `SingleSignOnService` endpoints (required by SAML).
    pub single_sign_on_service: Vec<Endpoint>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// `ArtifactResolutionService` endpoints. Each binding is SOAP.
    pub artifact_resolution_service: Vec<ArtifactResolutionEndpoint>,
    /// `ManageNameIDService` locations. Each binding is SOAP.
    pub manage_name_id_service: Vec<String>,
    /// Element ordering profile (defaults to [`elements_order::idp::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
}

fn write_key_descriptor(w: &mut MetadataWriter, use_: &str, cert: &str) {
    let cert = normalize_cert_string(cert);
    w.start("KeyDescriptor", &[("use", use_)]);
    w.start("ds:KeyInfo", &[("xmlns:ds", namespace::DSIG)]);
    w.start("ds:X509Data", &[]);
    w.text_element("ds:X509Certificate", &cert);
    w.end("ds:X509Data");
    w.end("ds:KeyInfo");
    w.end("KeyDescriptor");
}

fn write_key_descriptors(w: &mut MetadataWriter, signing: &[String], encrypt: &[String]) {
    for cert in signing {
        write_key_descriptor(w, "signing", cert);
    }
    for cert in encrypt {
        write_key_descriptor(w, "encryption", cert);
    }
}

fn write_name_id_formats(w: &mut MetadataWriter, formats: &[String], default_to_email: bool) {
    if is_non_empty_array(formats) {
        for format in formats {
            w.text_element("NameIDFormat", format);
        }
    } else if default_to_email {
        w.text_element("NameIDFormat", name_id_format::EMAIL_ADDRESS);
    }
}

fn write_endpoint_attrs(w: &mut MetadataWriter, name: &str, e: &Endpoint, index: Option<String>) {
    let mut attrs = Vec::with_capacity(4);
    if let Some(index) = index.as_deref() {
        attrs.push(("index", index));
    }
    if e.is_default {
        attrs.push(("isDefault", "true"));
    }
    attrs.push(("Binding", e.binding.urn()));
    attrs.push(("Location", e.location.as_str()));
    w.empty(name, &attrs);
}

fn write_single_logout(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        write_endpoint_attrs(w, "SingleLogoutService", endpoint, None);
    }
}

fn write_assertion_consumer_service(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for (i, endpoint) in endpoints.iter().enumerate() {
        let index = endpoint
            .index
            .map(|index| index.to_string())
            .unwrap_or_else(|| i.to_string());
        write_endpoint_attrs(w, "AssertionConsumerService", endpoint, Some(index));
    }
}

fn write_single_sign_on_service(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        write_endpoint_attrs(w, "SingleSignOnService", endpoint, None);
    }
}

fn write_artifact_resolution_service(
    w: &mut MetadataWriter,
    endpoints: &[ArtifactResolutionEndpoint],
) {
    for endpoint in endpoints {
        let index = endpoint.index.to_string();
        w.empty(
            "ArtifactResolutionService",
            &[
                ("index", index.as_str()),
                ("Binding", crate::constants::SOAP_BINDING_URN),
                ("Location", endpoint.location.as_str()),
            ],
        );
    }
}

fn write_manage_name_id_service(w: &mut MetadataWriter, locations: &[String]) {
    for location in locations {
        w.empty(
            "ManageNameIDService",
            &[
                ("Binding", crate::constants::SOAP_BINDING_URN),
                ("Location", location.as_str()),
            ],
        );
    }
}

fn write_sp_group(w: &mut MetadataWriter, cfg: &SpMetadataConfig, name: &str) {
    match name {
        "KeyDescriptor" => write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs),
        "NameIDFormat" => write_name_id_formats(w, &cfg.name_id_format, true),
        "SingleLogoutService" => write_single_logout(w, &cfg.single_logout_service),
        "AssertionConsumerService" => {
            write_assertion_consumer_service(w, &cfg.assertion_consumer_service)
        }
        _ => {}
    }
}

fn idp_group_has_content(cfg: &IdpMetadataConfig, name: &str) -> bool {
    match name {
        "KeyDescriptor" => {
            is_non_empty_array(&cfg.signing_certs) || is_non_empty_array(&cfg.encrypt_certs)
        }
        "NameIDFormat" => is_non_empty_array(&cfg.name_id_format),
        "SingleSignOnService" => is_non_empty_array(&cfg.single_sign_on_service),
        "SingleLogoutService" => is_non_empty_array(&cfg.single_logout_service),
        "ArtifactResolutionService" => is_non_empty_array(&cfg.artifact_resolution_service),
        "ManageNameIDService" => is_non_empty_array(&cfg.manage_name_id_service),
        _ => false,
    }
}

fn write_idp_group(w: &mut MetadataWriter, cfg: &IdpMetadataConfig, name: &str) {
    match name {
        "KeyDescriptor" => write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs),
        "NameIDFormat" => write_name_id_formats(w, &cfg.name_id_format, false),
        "SingleSignOnService" => write_single_sign_on_service(w, &cfg.single_sign_on_service),
        "SingleLogoutService" => write_single_logout(w, &cfg.single_logout_service),
        "ArtifactResolutionService" => {
            write_artifact_resolution_service(w, &cfg.artifact_resolution_service)
        }
        "ManageNameIDService" => write_manage_name_id_service(w, &cfg.manage_name_id_service),
        _ => {}
    }
}

fn elements_order_or_default(order: &Option<Vec<String>>, default: &[&str]) -> Vec<String> {
    if let Some(order) = order {
        order.clone()
    } else {
        default.iter().map(|s| s.to_string()).collect()
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Generate SP metadata XML.
pub fn generate_sp_metadata(cfg: &SpMetadataConfig) -> String {
    let is_custom_order = cfg.elements_order.is_some();
    let order = elements_order_or_default(&cfg.elements_order, elements_order::DEFAULT);
    let mut w = MetadataWriter::new();
    w.start(
        "EntityDescriptor",
        &[
            ("entityID", cfg.entity_id.as_str()),
            ("xmlns", namespace::METADATA),
            ("xmlns:assertion", namespace::ASSERTION),
            ("xmlns:ds", namespace::DSIG),
        ],
    );
    w.start(
        "SPSSODescriptor",
        &[
            ("AuthnRequestsSigned", bool_str(cfg.authn_requests_signed)),
            ("WantAssertionsSigned", bool_str(cfg.want_assertions_signed)),
            ("protocolSupportEnumeration", namespace::PROTOCOL),
        ],
    );
    for name in &order {
        write_sp_group(&mut w, cfg, name);
    }
    if is_custom_order
        && !order
            .iter()
            .any(|ordered| ordered == "AssertionConsumerService")
    {
        write_sp_group(&mut w, cfg, "AssertionConsumerService");
    }
    w.end("SPSSODescriptor");
    w.end("EntityDescriptor");
    w.finish()
}

/// Generate IdP metadata XML.
pub fn generate_idp_metadata(cfg: &IdpMetadataConfig) -> String {
    let is_custom_order = cfg.elements_order.is_some();
    let mut order = elements_order_or_default(&cfg.elements_order, elements_order::idp::DEFAULT);
    if is_custom_order
        && !order
            .iter()
            .any(|ordered| ordered == "ArtifactResolutionService")
    {
        let after_key_descriptor = order
            .iter()
            .position(|ordered| ordered == "KeyDescriptor")
            .map_or(0, |position| position + 1);
        order.insert(after_key_descriptor, "ArtifactResolutionService".into());
    }
    if is_custom_order && !order.iter().any(|ordered| ordered == "ManageNameIDService") {
        let after_single_logout = order
            .iter()
            .position(|ordered| ordered == "SingleLogoutService")
            .map_or(order.len(), |position| position + 1);
        order.insert(after_single_logout, "ManageNameIDService".into());
    }
    let descriptors = [
        "KeyDescriptor",
        "NameIDFormat",
        "ArtifactResolutionService",
        "SingleSignOnService",
        "SingleLogoutService",
        "ManageNameIDService",
    ];
    let mut w = MetadataWriter::new();
    w.start(
        "EntityDescriptor",
        &[
            ("entityID", cfg.entity_id.as_str()),
            ("xmlns", namespace::METADATA),
            ("xmlns:assertion", namespace::ASSERTION),
            ("xmlns:ds", namespace::DSIG),
        ],
    );
    w.start(
        "IDPSSODescriptor",
        &[
            (
                "WantAuthnRequestsSigned",
                bool_str(cfg.want_authn_requests_signed),
            ),
            ("protocolSupportEnumeration", namespace::PROTOCOL),
        ],
    );
    for name in &order {
        if descriptors.contains(&name.as_str()) && idp_group_has_content(cfg, name) {
            write_idp_group(&mut w, cfg, name);
        }
    }
    if is_custom_order {
        if !order.iter().any(|ordered| ordered == "SingleSignOnService") {
            write_idp_group(&mut w, cfg, "SingleSignOnService");
        }
    } else {
        for name in descriptors {
            if idp_group_has_content(cfg, name) && !order.iter().any(|ordered| ordered == name) {
                write_idp_group(&mut w, cfg, name);
            }
        }
    }
    w.end("IDPSSODescriptor");
    w.end("EntityDescriptor");
    w.finish()
}

/// Generate IdP metadata XML, validating required config-driven metadata first.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config does not include at
/// least one `SingleSignOnService` endpoint.
pub fn try_generate_idp_metadata(cfg: &IdpMetadataConfig) -> Result<String, SamlError> {
    if !is_non_empty_array(&cfg.single_sign_on_service) {
        return Err(SamlError::MissingMetadata(
            "SingleSignOnService".to_string(),
        ));
    }
    Ok(generate_idp_metadata(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CertUse;
    use crate::entity::EntitySetting;
    use crate::metadata::{IdpMetadata, SpMetadata};
    use crate::sp::ServiceProvider;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn sp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            encrypt_certs: vec!["MIIBencrypt".into()],
            authn_requests_signed: true,
            want_assertions_signed: true,
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_logout_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://sp.example.com/slo",
            )],
            assertion_consumer_service: vec![
                Endpoint {
                    binding: Binding::Post,
                    location: "https://sp.example.com/acs".into(),
                    index: None,
                    is_default: true,
                },
                Endpoint::new(Binding::Redirect, "https://sp.example.com/acs-redirect"),
            ],
            elements_order: None,
        };
        let xml = generate_sp_metadata(&cfg);
        let parsed = SpMetadata::from_xml(&xml)?;
        assert_eq!(
            parsed.get_entity_id(),
            Some("https://sp.example.com/metadata")
        );
        assert!(parsed.is_authn_request_signed());
        assert!(parsed.is_want_assertions_signed());
        assert_eq!(
            parsed
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert_eq!(
            parsed
                .get_single_logout_service(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.com/slo")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Signing).as_deref(),
            Some("MIIBsigning")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Encryption).as_deref(),
            Some("MIIBencrypt")
        );
        Ok(())
    }

    #[test]
    fn sp_elements_order_respected() {
        let cfg = SpMetadataConfig {
            entity_id: "x".into(),
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        };
        let xml = generate_sp_metadata(&cfg);
        let slo = xml.find("SingleLogoutService").unwrap_or(usize::MAX);
        let acs = xml.find("AssertionConsumerService").unwrap_or(0);
        // default order places SingleLogoutService before AssertionConsumerService
        assert!(slo < acs);
    }

    #[test]
    fn idp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBidp".into()],
            want_authn_requests_signed: true,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        };
        let xml = generate_idp_metadata(&cfg);
        let parsed = IdpMetadata::from_xml(&xml)?;
        assert!(parsed.is_want_authn_requests_signed());
        assert_eq!(
            parsed
                .get_single_sign_on_service(Binding::Redirect)
                .as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Signing).as_deref(),
            Some("MIIBidp")
        );
        Ok(())
    }

    #[test]
    fn try_generate_idp_metadata_rejects_missing_sso() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            ..Default::default()
        };

        let result = try_generate_idp_metadata(&cfg);

        assert!(matches!(
            result,
            Err(SamlError::MissingMetadata(name)) if name == "SingleSignOnService"
        ));
    }

    #[test]
    fn sp_from_config_escapes_name_id_format_xml_markup() -> TestResult {
        let injected_format = format!(
            "{}</NameIDFormat><SingleLogoutService Binding=\"{}\" Location=\"https://evil.example/slo\"/><NameIDFormat>",
            name_id_format::EMAIL_ADDRESS,
            Binding::Redirect.urn()
        );
        let cfg = SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            name_id_format: vec![injected_format.clone()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        };

        let sp = ServiceProvider::from_config(&cfg, EntitySetting::default())?;

        assert!(sp
            .metadata
            .get_single_logout_service(Binding::Redirect)
            .is_none());
        assert_eq!(sp.setting.name_id_format, vec![injected_format]);
        assert!(sp.metadata_xml().contains("&lt;SingleLogoutService"));
        Ok(())
    }

    #[test]
    fn sp_metadata_escapes_entity_id_attribute_markup() -> TestResult {
        let entity_id = "https://sp.example.com/metadata\" ID=\"_evil";
        let cfg = SpMetadataConfig {
            entity_id: entity_id.into(),
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        };

        let xml = generate_sp_metadata(&cfg);
        let parsed = SpMetadata::from_xml(&xml)?;

        assert!(!xml.contains(" ID=\"_evil\""));
        assert!(xml.contains("&quot; ID=&quot;_evil"));
        assert_eq!(parsed.get_entity_id(), Some(entity_id));
        Ok(())
    }

    #[test]
    fn sp_metadata_escapes_certificate_text_markup() -> TestResult {
        let injected_cert = concat!(
            "MIIB</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>",
            "<NameIDFormat>evil</NameIDFormat>",
            "<KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>tail"
        );
        let cfg = SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec![injected_cert.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            elements_order: Some(vec![
                "KeyDescriptor".into(),
                "AssertionConsumerService".into(),
            ]),
            ..Default::default()
        };

        let xml = generate_sp_metadata(&cfg);
        let parsed = SpMetadata::from_xml(&xml)?;

        assert!(xml.contains("&lt;NameIDFormat&gt;evil&lt;/NameIDFormat&gt;"));
        assert!(parsed.get_name_id_format().is_empty());
        assert_eq!(parsed.x509_certificates(CertUse::Signing).len(), 1);
        Ok(())
    }

    #[test]
    fn sp_custom_elements_order_preserves_omitted_populated_acs() {
        let cfg = SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            elements_order: Some(vec!["KeyDescriptor".into()]),
            ..Default::default()
        };

        let xml = generate_sp_metadata(&cfg);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let acs = xml.find("<AssertionConsumerService").unwrap_or(usize::MAX);

        assert_eq!(xml.matches("<AssertionConsumerService").count(), 1);
        assert!(key < acs);
        assert!(!xml.contains("<NameIDFormat"));
        assert!(!xml.contains("<SingleLogoutService"));
    }

    #[test]
    fn idp_metadata_escapes_endpoint_location_attribute_markup() -> TestResult {
        let injected_location = format!(
            "https://idp/sso\"/><SingleLogoutService Binding=\"{}\" Location=\"https://evil.example/slo",
            Binding::Redirect.urn()
        );
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                injected_location.clone(),
            )],
            ..Default::default()
        };

        let xml = try_generate_idp_metadata(&cfg)?;
        let parsed = IdpMetadata::from_xml(&xml)?;

        assert!(!xml.contains("<SingleLogoutService"));
        assert_eq!(
            parsed
                .get_single_sign_on_service(Binding::Redirect)
                .as_deref(),
            Some(injected_location.as_str())
        );
        assert!(parsed
            .get_single_logout_service(Binding::Redirect)
            .is_none());
        Ok(())
    }

    #[test]
    fn idp_default_elements_order_matches_historical_output() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let name_id = xml.find("<NameIDFormat").unwrap_or(usize::MAX);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);
        let slo = xml.find("<SingleLogoutService").unwrap_or(usize::MAX);

        assert!(key < name_id);
        assert!(name_id < sso);
        assert!(sso < slo);
    }

    #[test]
    fn idp_custom_elements_order_can_place_sso_before_key_descriptor() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec![
                "SingleSignOnService".into(),
                "KeyDescriptor".into(),
                "NameIDFormat".into(),
                "SingleLogoutService".into(),
            ]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let name_id = xml.find("<NameIDFormat").unwrap_or(usize::MAX);
        let slo = xml.find("<SingleLogoutService").unwrap_or(usize::MAX);

        assert!(sso < key);
        assert!(key < name_id);
        assert!(name_id < slo);
    }

    #[test]
    fn idp_elements_order_filters_empty_groups() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec![
                "KeyDescriptor".into(),
                "NameIDFormat".into(),
                "SingleSignOnService".into(),
                "SingleLogoutService".into(),
            ]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);

        assert!(!xml.contains("<KeyDescriptor"));
        assert!(!xml.contains("<NameIDFormat"));
        assert!(xml.contains("<SingleSignOnService"));
        assert!(xml.contains("<SingleLogoutService"));
    }

    #[test]
    fn idp_custom_elements_order_omits_unlisted_optional_groups() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec!["SingleSignOnService".into()]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);

        assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
        assert!(!xml.contains("<KeyDescriptor"));
        assert!(!xml.contains("<NameIDFormat"));
        assert!(!xml.contains("<SingleLogoutService"));
    }

    #[test]
    fn idp_custom_elements_order_preserves_omitted_populated_sso() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            elements_order: Some(vec!["KeyDescriptor".into()]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);

        assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
        assert!(key < sso);
    }

    #[test]
    fn idp_custom_elements_order_writes_omitted_manage_name_id_service_after_logout() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            name_id_format: vec![name_id_format::PERSISTENT.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            manage_name_id_service: vec!["https://idp/nameid".into()],
            elements_order: Some(
                elements_order::idp::SHIBBOLETH
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect(),
            ),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let positions = [
            "<SingleLogoutService",
            "<ManageNameIDService",
            "<NameIDFormat",
            "<SingleSignOnService",
        ]
        .map(|element| xml.find(element));

        assert!(xml.contains(
            r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp/nameid"/>"#
        ));
        assert_eq!(xml.matches("<ManageNameIDService").count(), 1);
        assert!(positions.iter().all(Option::is_some));
        assert!(positions.is_sorted());
    }

    #[test]
    fn idp_custom_elements_order_writes_omitted_artifact_resolution_after_keys() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            artifact_resolution_service: vec![ArtifactResolutionEndpoint {
                index: 0,
                location: "https://idp/artifact".into(),
            }],
            elements_order: Some(
                elements_order::idp::SHIBBOLETH
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect(),
            ),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let positions = [
            "<KeyDescriptor",
            "<ArtifactResolutionService",
            "<SingleLogoutService",
            "<NameIDFormat",
            "<SingleSignOnService",
        ]
        .map(|element| xml.find(element));

        assert_eq!(xml.matches("<ArtifactResolutionService").count(), 1);
        assert!(positions.iter().all(Option::is_some));
        assert!(positions.is_sorted());
    }

    #[test]
    fn idp_elements_order_profiles_match_upstream() {
        // The default profile includes ArtifactResolutionService. OneLogin and
        // Shibboleth stay the upstream lists; generation writes the service
        // after KeyDescriptor when a custom list omits it.
        assert_eq!(
            elements_order::idp::DEFAULT,
            [
                "KeyDescriptor",
                "NameIDFormat",
                "ArtifactResolutionService",
                "SingleSignOnService",
                "SingleLogoutService",
            ]
        );
        assert_eq!(
            elements_order::idp::ONELOGIN,
            [
                "KeyDescriptor",
                "NameIDFormat",
                "SingleLogoutService",
                "SingleSignOnService",
            ]
        );
        assert_eq!(
            elements_order::idp::SHIBBOLETH,
            [
                "KeyDescriptor",
                "SingleLogoutService",
                "NameIDFormat",
                "SingleSignOnService",
            ]
        );
    }
}
