//! SAML SP and IdP metadata generation.

use std::collections::HashSet;

use crate::config::validate_entity_id_syntax;
use crate::constants::{elements_order, name_id_format, namespace, Binding};
use crate::error::SamlError;
use crate::metadata::description::{validate_description, write_description};
use crate::metadata::lifetime::{LifetimeAttributes, MetadataLifetime};
use crate::metadata::write::MetadataWriter;
use crate::model::validate_name_id_format;
use crate::util::normalize_cert_string;

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
    ///
    /// An ACS without one is written with its position in the list. When
    /// another ACS already has that index, it gets the smallest index no
    /// other ACS uses.
    pub index: Option<u16>,
    /// Writes `isDefault="true"` on an `AssertionConsumerService`; ignored for
    /// other endpoint kinds.
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
    /// `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<Endpoint>,
    /// Element ordering profile (defaults to [`elements_order::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
    /// `validUntil` and `cacheDuration` on the `EntityDescriptor`. `None`
    /// writes neither.
    pub lifetime: Option<MetadataLifetime>,
    /// Entity-level organization. `None` writes no `Organization`.
    pub organization: Option<crate::metadata::Organization>,
    /// Entity-level contacts, in publication order.
    pub contacts: Vec<crate::metadata::ContactPerson>,
    /// Error information URI on the SSO role descriptor. `None` omits it.
    pub error_url: Option<String>,
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
    /// `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<Endpoint>,
    /// Element ordering profile (defaults to [`elements_order::idp::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
    /// `validUntil` and `cacheDuration` on the `EntityDescriptor`. `None`
    /// writes neither.
    pub lifetime: Option<MetadataLifetime>,
    /// Entity-level organization. `None` writes no `Organization`.
    pub organization: Option<crate::metadata::Organization>,
    /// Entity-level contacts, in publication order.
    pub contacts: Vec<crate::metadata::ContactPerson>,
    /// Error information URI on the SSO role descriptor. `None` omits it.
    pub error_url: Option<String>,
}

fn write_entity_descriptor_start(
    w: &mut MetadataWriter,
    entity_id: &str,
    lifetime: Option<MetadataLifetime>,
) -> Result<(), SamlError> {
    let lifetime = LifetimeAttributes::new(lifetime)?;
    let mut attributes = vec![("entityID", entity_id)];
    attributes.extend(lifetime.attributes());
    attributes.extend([
        ("xmlns", namespace::METADATA),
        ("xmlns:assertion", namespace::ASSERTION),
        ("xmlns:ds", namespace::DSIG),
    ]);
    w.start("EntityDescriptor", &attributes);
    Ok(())
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

fn write_name_id_formats(
    w: &mut MetadataWriter,
    formats: &[String],
    default_to_email: bool,
) -> Result<(), SamlError> {
    if !formats.is_empty() {
        for format in formats {
            validate_name_id_format(Some(format))?;
            w.text_element("NameIDFormat", format);
        }
    } else if default_to_email {
        w.text_element("NameIDFormat", name_id_format::EMAIL_ADDRESS);
    }
    Ok(())
}

fn write_endpoint(w: &mut MetadataWriter, name: &str, e: &Endpoint) {
    w.empty(
        name,
        &[
            ("Binding", e.binding.urn()),
            ("Location", e.location.as_str()),
        ],
    );
}

fn write_single_logout(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        write_endpoint(w, "SingleLogoutService", endpoint);
    }
}

fn assertion_consumer_service_indexes(endpoints: &[Endpoint]) -> Result<Vec<u16>, SamlError> {
    let mut explicit = HashSet::new();
    for index in endpoints.iter().filter_map(|endpoint| endpoint.index) {
        if !explicit.insert(index) {
            return Err(SamlError::Invalid(format!(
                "duplicate AssertionConsumerService index {index}"
            )));
        }
    }
    let indexes: Vec<Option<u16>> = endpoints
        .iter()
        .enumerate()
        .map(|(position, endpoint)| {
            endpoint.index.or_else(|| {
                u16::try_from(position)
                    .ok()
                    .filter(|index| !explicit.contains(index))
            })
        })
        .collect();
    let used: HashSet<u16> = indexes.iter().flatten().copied().collect();
    let mut unused = (0..=u16::MAX).filter(|index| !used.contains(index));
    indexes
        .into_iter()
        .map(|index| {
            index.or_else(|| unused.next()).ok_or_else(|| {
                SamlError::Invalid("more AssertionConsumerService endpoints than indexes".into())
            })
        })
        .collect()
}

fn write_assertion_consumer_service(
    w: &mut MetadataWriter,
    endpoints: &[Endpoint],
) -> Result<(), SamlError> {
    let indexes = assertion_consumer_service_indexes(endpoints)?;
    for (endpoint, index) in endpoints.iter().zip(indexes) {
        let index = index.to_string();
        let mut attrs = vec![("index", index.as_str())];
        if endpoint.is_default {
            attrs.push(("isDefault", "true"));
        }
        attrs.push(("Binding", endpoint.binding.urn()));
        attrs.push(("Location", endpoint.location.as_str()));
        w.empty("AssertionConsumerService", &attrs);
    }
    Ok(())
}

fn write_single_sign_on_service(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        write_endpoint(w, "SingleSignOnService", endpoint);
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

fn write_manage_name_id_service(w: &mut MetadataWriter, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        write_endpoint(w, "ManageNameIDService", endpoint);
    }
}

fn write_sp_group(
    w: &mut MetadataWriter,
    cfg: &SpMetadataConfig,
    name: &str,
) -> Result<(), SamlError> {
    match name {
        "KeyDescriptor" => write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs),
        "NameIDFormat" => write_name_id_formats(w, &cfg.name_id_format, true)?,
        "SingleLogoutService" => write_single_logout(w, &cfg.single_logout_service),
        "ManageNameIDService" => write_manage_name_id_service(w, &cfg.manage_name_id_service),
        "AssertionConsumerService" => {
            write_assertion_consumer_service(w, &cfg.assertion_consumer_service)?
        }
        _ => {}
    }
    Ok(())
}

fn write_idp_group(
    w: &mut MetadataWriter,
    cfg: &IdpMetadataConfig,
    name: &str,
) -> Result<(), SamlError> {
    match name {
        "KeyDescriptor" => write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs),
        "NameIDFormat" => write_name_id_formats(w, &cfg.name_id_format, false)?,
        "SingleSignOnService" => write_single_sign_on_service(w, &cfg.single_sign_on_service),
        "SingleLogoutService" => write_single_logout(w, &cfg.single_logout_service),
        "ArtifactResolutionService" => {
            write_artifact_resolution_service(w, &cfg.artifact_resolution_service)
        }
        "ManageNameIDService" => write_manage_name_id_service(w, &cfg.manage_name_id_service),
        _ => {}
    }
    Ok(())
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

fn insert_manage_name_id_service(order: &mut Vec<String>) {
    let before_role_elements = order
        .iter()
        .position(|ordered| {
            matches!(
                ordered.as_str(),
                "NameIDFormat"
                    | "SingleSignOnService"
                    | "AssertionConsumerService"
                    | "AttributeConsumingService"
            )
        })
        .unwrap_or(order.len());
    order.insert(before_role_elements, "ManageNameIDService".into());
}

/// Generate SP metadata XML.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, when a `<NameIDFormat>` it writes is
/// not an absolute URI reference, when two `AssertionConsumerService`
/// endpoints set the same [`Endpoint::index`], or when there are more of them
/// than `unsignedShort` indexes. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry.
pub fn generate_sp_metadata(cfg: &SpMetadataConfig) -> Result<String, SamlError> {
    validate_entity_id_syntax(&cfg.entity_id)?;
    validate_description(
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
    )?;
    let is_custom_order = cfg.elements_order.is_some();
    let mut order = elements_order_or_default(&cfg.elements_order, elements_order::DEFAULT);
    if !order.iter().any(|ordered| ordered == "ManageNameIDService") {
        insert_manage_name_id_service(&mut order);
    }
    let mut w = MetadataWriter::new();
    write_entity_descriptor_start(&mut w, &cfg.entity_id, cfg.lifetime)?;
    let mut role_attributes = vec![
        ("AuthnRequestsSigned", bool_str(cfg.authn_requests_signed)),
        ("WantAssertionsSigned", bool_str(cfg.want_assertions_signed)),
        ("protocolSupportEnumeration", namespace::PROTOCOL),
    ];
    if let Some(error_url) = &cfg.error_url {
        role_attributes.push(("errorURL", error_url));
    }
    w.start("SPSSODescriptor", &role_attributes);
    for name in &order {
        write_sp_group(&mut w, cfg, name)?;
    }
    if is_custom_order
        && !order
            .iter()
            .any(|ordered| ordered == "AssertionConsumerService")
    {
        write_sp_group(&mut w, cfg, "AssertionConsumerService")?;
    }
    w.end("SPSSODescriptor");
    write_description(&mut w, cfg.organization.as_ref(), &cfg.contacts);
    w.end("EntityDescriptor");
    Ok(w.finish())
}

/// Generate IdP metadata XML.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, or when a `<NameIDFormat>` it writes
/// is not an absolute URI reference. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry.
pub fn generate_idp_metadata(cfg: &IdpMetadataConfig) -> Result<String, SamlError> {
    validate_entity_id_syntax(&cfg.entity_id)?;
    validate_description(
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
    )?;
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
        insert_manage_name_id_service(&mut order);
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
    write_entity_descriptor_start(&mut w, &cfg.entity_id, cfg.lifetime)?;
    let mut role_attributes = vec![
        (
            "WantAuthnRequestsSigned",
            bool_str(cfg.want_authn_requests_signed),
        ),
        ("protocolSupportEnumeration", namespace::PROTOCOL),
    ];
    if let Some(error_url) = &cfg.error_url {
        role_attributes.push(("errorURL", error_url));
    }
    w.start("IDPSSODescriptor", &role_attributes);
    for name in &order {
        write_idp_group(&mut w, cfg, name)?;
    }
    if is_custom_order {
        if !order.iter().any(|ordered| ordered == "SingleSignOnService") {
            write_idp_group(&mut w, cfg, "SingleSignOnService")?;
        }
    } else {
        for name in descriptors {
            if !order.iter().any(|ordered| ordered == name) {
                write_idp_group(&mut w, cfg, name)?;
            }
        }
    }
    w.end("IDPSSODescriptor");
    write_description(&mut w, cfg.organization.as_ref(), &cfg.contacts);
    w.end("EntityDescriptor");
    Ok(w.finish())
}

/// Generate IdP metadata XML, validating required config-driven metadata first.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config does not include at
/// least one `SingleSignOnService` endpoint, and the errors of
/// [`generate_idp_metadata`].
pub fn try_generate_idp_metadata(cfg: &IdpMetadataConfig) -> Result<String, SamlError> {
    if cfg.single_sign_on_service.is_empty() {
        return Err(SamlError::MissingMetadata(
            "SingleSignOnService".to_string(),
        ));
    }
    generate_idp_metadata(cfg)
}

#[cfg(test)]
mod tests;
