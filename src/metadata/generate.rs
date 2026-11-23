//! SAML SP and IdP metadata generation.

use std::collections::HashSet;

use crate::config::validate_entity_id_syntax;
use crate::constants::{name_id_format, namespace, Binding};
use crate::error::SamlError;
use crate::metadata::description::{validate_description, write_description};
use crate::metadata::lifetime::{LifetimeAttributes, MetadataLifetime};
use crate::metadata::write::MetadataWriter;
use crate::model::validate_name_id_format;
use crate::util::normalize_cert_string;

/// A protocol endpoint (`SingleSignOnService` / `SingleLogoutService` / ACS).
///
/// Start from [`Self::new`] and assign the fields you set.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
///
/// Start from [`Default`](Default::default) and assign the fields you set.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SpMetadataInput {
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
    /// `AssertionConsumerService` endpoints (required by SAML).
    pub assertion_consumer_service: Vec<Endpoint>,
    /// `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<Endpoint>,
    /// Lifetime on the root `EntityDescriptor`. `None` writes `cacheDuration="PT86400S"`.
    pub lifetime: Option<MetadataLifetime>,
    /// Entity-level organization. `None` writes no `Organization`.
    pub organization: Option<crate::metadata::Organization>,
    /// Entity-level contacts, in publication order.
    pub contacts: Vec<crate::metadata::ContactPerson>,
    /// Error information URI on the SSO role descriptor. `None` omits it.
    pub error_url: Option<String>,
}

/// IdP metadata generation input.
///
/// Start from [`Default`](Default::default) and assign the fields you set.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct IdpMetadataInput {
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
    pub artifact_resolution_service: Vec<crate::ArtifactResolutionService>,
    /// `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<Endpoint>,
    /// Lifetime on the root `EntityDescriptor`. `None` writes `cacheDuration="PT86400S"`.
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

fn write_name_id_formats(w: &mut MetadataWriter, formats: &[String]) -> Result<(), SamlError> {
    for format in formats {
        validate_name_id_format(Some(format))?;
        w.text_element("NameIDFormat", format);
    }
    Ok(())
}

fn write_endpoints(w: &mut MetadataWriter, name: &str, endpoints: &[Endpoint]) {
    for endpoint in endpoints {
        w.empty(
            name,
            &[
                ("Binding", endpoint.binding.urn()),
                ("Location", endpoint.location.as_str()),
            ],
        );
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
    let positional: Vec<Option<u16>> = endpoints
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
    let used: HashSet<u16> = positional.iter().flatten().copied().collect();
    let mut unused = (0..=u16::MAX).filter(|index| !used.contains(index));
    let mut indexes = Vec::with_capacity(positional.len());
    for index in positional {
        let index = match index {
            Some(index) => index,
            None => unused.next().ok_or_else(|| {
                SamlError::Invalid("more AssertionConsumerService endpoints than indexes".into())
            })?,
        };
        indexes.push(index);
    }
    Ok(indexes)
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

fn write_artifact_resolution_service(
    w: &mut MetadataWriter,
    endpoints: &[crate::ArtifactResolutionService],
) {
    for endpoint in endpoints {
        let index = endpoint.index().to_string();
        w.empty(
            "ArtifactResolutionService",
            &[
                ("index", index.as_str()),
                ("Binding", Binding::Soap.urn()),
                ("Location", endpoint.location().as_str()),
            ],
        );
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Generate SP metadata XML with role children in schema order.
///
/// Endpoints within each group appear in input order.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config has no
/// `AssertionConsumerService` endpoint.
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, when a `<NameIDFormat>` it writes is
/// not an absolute URI reference, when two `AssertionConsumerService`
/// endpoints set the same [`Endpoint::index`], or when there are more of them
/// than `unsignedShort` indexes. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry.
pub fn generate_sp_metadata(cfg: &SpMetadataInput) -> Result<String, SamlError> {
    if cfg.assertion_consumer_service.is_empty() {
        return Err(SamlError::MissingMetadata(
            "AssertionConsumerService".to_string(),
        ));
    }
    validate_entity_id_syntax(&cfg.entity_id)?;
    validate_description(
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
    )?;
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
    write_key_descriptors(&mut w, &cfg.signing_certs, &cfg.encrypt_certs);
    write_endpoints(&mut w, "SingleLogoutService", &cfg.single_logout_service);
    write_endpoints(&mut w, "ManageNameIDService", &cfg.manage_name_id_service);
    if cfg.name_id_format.is_empty() {
        w.text_element("NameIDFormat", name_id_format::EMAIL_ADDRESS);
    } else {
        write_name_id_formats(&mut w, &cfg.name_id_format)?;
    }
    write_assertion_consumer_service(&mut w, &cfg.assertion_consumer_service)?;
    w.end("SPSSODescriptor");
    write_description(&mut w, cfg.organization.as_ref(), &cfg.contacts);
    w.end("EntityDescriptor");
    Ok(w.finish())
}

/// Generate IdP metadata XML with role children in schema order.
///
/// Endpoints within each group appear in input order.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config has no
/// `SingleSignOnService` endpoint.
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, or when a `<NameIDFormat>` it writes
/// is not an absolute URI reference. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry.
pub fn generate_idp_metadata(cfg: &IdpMetadataInput) -> Result<String, SamlError> {
    if cfg.single_sign_on_service.is_empty() {
        return Err(SamlError::MissingMetadata(
            "SingleSignOnService".to_string(),
        ));
    }
    validate_entity_id_syntax(&cfg.entity_id)?;
    validate_description(
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
    )?;
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
    write_key_descriptors(&mut w, &cfg.signing_certs, &cfg.encrypt_certs);
    write_artifact_resolution_service(&mut w, &cfg.artifact_resolution_service);
    write_endpoints(&mut w, "SingleLogoutService", &cfg.single_logout_service);
    write_endpoints(&mut w, "ManageNameIDService", &cfg.manage_name_id_service);
    write_name_id_formats(&mut w, &cfg.name_id_format)?;
    write_endpoints(&mut w, "SingleSignOnService", &cfg.single_sign_on_service);
    w.end("IDPSSODescriptor");
    write_description(&mut w, cfg.organization.as_ref(), &cfg.contacts);
    w.end("EntityDescriptor");
    Ok(w.finish())
}

#[cfg(test)]
mod tests;
