//! SAML SP and IdP metadata generation.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::config::validate_entity_id_syntax;
use crate::constants::{name_id_format, namespace, Binding};
use crate::error::SamlError;
use crate::metadata::description::{validate_description, write_description};
use crate::metadata::entity_attributes::{validate_entity_attributes, write_entity_attributes};
use crate::metadata::lifetime::{LifetimeAttributes, MetadataLifetime};
use crate::metadata::write::MetadataWriter;
use crate::metadata::{ContactPerson, Organization};
use crate::model::{validate_name_id_format, Attribute};
use crate::util::normalize_cert_string;
use crate::xml::any_uri::is_absolute_uri_reference;

/// A protocol endpoint (`SingleSignOnService` / `SingleLogoutService` / ACS).
///
/// Start from [`Self::new`] and assign the fields you set.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Endpoint {
    /// Protocol binding.
    pub binding: Binding,
    /// Endpoint `Location`, an absolute URI reference.
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
    /// Signing X.509 certificates in PEM or as bare base64-encoded DER.
    pub signing_certs: Vec<String>,
    /// Encryption X.509 certificates in PEM or as bare base64-encoded DER.
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
    /// Entity attributes, in publication order, written in one
    /// `mdattr:EntityAttributes`. Empty writes no `Extensions`.
    pub entity_attributes: Vec<Attribute>,
}

/// IdP metadata generation input.
///
/// Start from [`Default`](Default::default) and assign the fields you set.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct IdpMetadataInput {
    /// `entityID`.
    pub entity_id: String,
    /// Signing X.509 certificates in PEM or as bare base64-encoded DER.
    pub signing_certs: Vec<String>,
    /// Encryption X.509 certificates in PEM or as bare base64-encoded DER.
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
    /// Entity attributes, in publication order, written in one
    /// `mdattr:EntityAttributes`. Empty writes no `Extensions`.
    pub entity_attributes: Vec<Attribute>,
    /// Scope declarations published in the IdP role's `Extensions`, in order.
    /// Use lowercase letters in literal scopes (`regexp: false`).
    pub scopes: Vec<super::MetadataScope>,
}

fn generate_entity_descriptor(
    entity_id: &str,
    lifetime: Option<MetadataLifetime>,
    organization: Option<&Organization>,
    contacts: &[ContactPerson],
    error_url: Option<&str>,
    entity_attributes: &[Attribute],
    write_role: impl FnOnce(&mut MetadataWriter) -> Result<(), SamlError>,
) -> Result<String, SamlError> {
    validate_entity_id_syntax(entity_id)?;
    validate_description(organization, contacts, error_url)?;
    validate_entity_attributes(entity_attributes)?;
    let lifetime = LifetimeAttributes::new(lifetime)?;
    let mut attributes = vec![("entityID", entity_id)];
    attributes.extend(lifetime.attributes());
    attributes.extend([
        ("xmlns", namespace::METADATA),
        ("xmlns:assertion", namespace::ASSERTION),
        ("xmlns:ds", namespace::DSIG),
    ]);
    let mut w = MetadataWriter::new();
    w.start("EntityDescriptor", &attributes);
    write_entity_attributes(&mut w, entity_attributes);
    write_role(&mut w)?;
    write_description(&mut w, organization, contacts);
    w.end("EntityDescriptor");
    Ok(w.finish())
}

fn write_key_descriptor(w: &mut MetadataWriter, use_: &str, cert: &str) -> Result<(), SamlError> {
    let cert = normalize_cert_string(cert);
    if cert.is_empty() {
        return Err(SamlError::Invalid(format!("{use_} certificate is empty")));
    }
    STANDARD.decode(&cert).map_err(|source| SamlError::Base64 {
        source: Box::new(source),
    })?;
    w.start("KeyDescriptor", &[("use", use_)]);
    w.start("ds:KeyInfo", &[("xmlns:ds", namespace::DSIG)]);
    w.start("ds:X509Data", &[]);
    w.text_element("ds:X509Certificate", &cert);
    w.end("ds:X509Data");
    w.end("ds:KeyInfo");
    w.end("KeyDescriptor");
    Ok(())
}

fn write_key_descriptors(
    w: &mut MetadataWriter,
    signing: &[String],
    encrypt: &[String],
) -> Result<(), SamlError> {
    for cert in signing {
        write_key_descriptor(w, "signing", cert)?;
    }
    for cert in encrypt {
        write_key_descriptor(w, "encryption", cert)?;
    }
    Ok(())
}

fn write_name_id_formats(w: &mut MetadataWriter, formats: &[String]) -> Result<(), SamlError> {
    for format in formats {
        validate_name_id_format(Some(format))?;
        w.text_element("NameIDFormat", format);
    }
    Ok(())
}

fn endpoint_location<'a>(name: &str, location: &'a str) -> Result<&'a str, SamlError> {
    if !is_absolute_uri_reference(location) {
        return Err(SamlError::Invalid(format!(
            "{name} Location must be an absolute URI reference"
        )));
    }
    Ok(location)
}

fn write_endpoints(
    w: &mut MetadataWriter,
    name: &str,
    endpoints: &[Endpoint],
) -> Result<(), SamlError> {
    for endpoint in endpoints {
        w.empty(
            name,
            &[
                ("Binding", endpoint.binding.urn()),
                ("Location", endpoint_location(name, &endpoint.location)?),
            ],
        );
    }
    Ok(())
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
        attrs.push((
            "Location",
            endpoint_location("AssertionConsumerService", &endpoint.location)?,
        ));
        w.empty("AssertionConsumerService", &attrs);
    }
    Ok(())
}

fn write_artifact_resolution_service(
    w: &mut MetadataWriter,
    endpoints: &[crate::ArtifactResolutionService],
) -> Result<(), SamlError> {
    let mut indexes = HashSet::new();
    for endpoint in endpoints {
        if !indexes.insert(endpoint.index()) {
            return Err(SamlError::Invalid(format!(
                "duplicate ArtifactResolutionService index {}",
                endpoint.index()
            )));
        }
        let index = endpoint.index().to_string();
        w.empty(
            "ArtifactResolutionService",
            &[
                ("index", index.as_str()),
                ("Binding", Binding::Soap.urn()),
                (
                    "Location",
                    endpoint_location("ArtifactResolutionService", endpoint.location().as_str())?,
                ),
            ],
        );
    }
    Ok(())
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
/// Supply actual X.509 certificates. The generator checks their base64 text.
/// With a crypto provider, [`crate::SpConfigBuilder::build`] also loads X.509
/// certificates and checks that the private keys match.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config has no
/// `AssertionConsumerService` endpoint.
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, when a `<NameIDFormat>` or an
/// endpoint `Location` it writes is not an absolute URI reference, when two
/// `AssertionConsumerService` endpoints set the same [`Endpoint::index`], or
/// when there are more of them than `unsignedShort` indexes. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry,
/// and for an entity attribute whose `NameFormat` is not an absolute URI
/// reference, whose [`crate::AttributeNameFormat::Basic`] name is not an XML
/// name, or whose text XML cannot carry.
/// Returns [`SamlError::Invalid`] for an empty certificate and
/// [`SamlError::Base64`] for malformed base64 in a certificate.
pub fn generate_sp_metadata(cfg: &SpMetadataInput) -> Result<String, SamlError> {
    if cfg.assertion_consumer_service.is_empty() {
        return Err(SamlError::MissingMetadata(
            "AssertionConsumerService".to_string(),
        ));
    }
    generate_entity_descriptor(
        &cfg.entity_id,
        cfg.lifetime,
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
        &cfg.entity_attributes,
        |w| write_sp_role(w, cfg),
    )
}

fn write_sp_role(w: &mut MetadataWriter, cfg: &SpMetadataInput) -> Result<(), SamlError> {
    let mut role_attributes = vec![
        ("AuthnRequestsSigned", bool_str(cfg.authn_requests_signed)),
        ("WantAssertionsSigned", bool_str(cfg.want_assertions_signed)),
        ("protocolSupportEnumeration", namespace::PROTOCOL),
    ];
    if let Some(error_url) = &cfg.error_url {
        role_attributes.push(("errorURL", error_url));
    }
    w.start("SPSSODescriptor", &role_attributes);
    write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs)?;
    write_endpoints(w, "SingleLogoutService", &cfg.single_logout_service)?;
    write_endpoints(w, "ManageNameIDService", &cfg.manage_name_id_service)?;
    if cfg.name_id_format.is_empty() {
        w.text_element("NameIDFormat", name_id_format::EMAIL_ADDRESS);
    } else {
        write_name_id_formats(w, &cfg.name_id_format)?;
    }
    write_assertion_consumer_service(w, &cfg.assertion_consumer_service)?;
    w.end("SPSSODescriptor");
    Ok(())
}

/// Generate IdP metadata XML with role children in schema order.
///
/// Endpoints within each group appear in input order.
/// Supply actual X.509 certificates. The generator checks their base64 text.
/// With a crypto provider, [`crate::IdpConfigBuilder::build`] also loads X.509
/// certificates and checks that the private keys match.
///
/// # Errors
///
/// Returns [`SamlError::MissingMetadata`] when the config has no
/// `SingleSignOnService` endpoint.
/// Returns [`SamlError::Invalid`] when the `entityID` is not an absolute URI
/// reference of at most 1024 characters, when a `<NameIDFormat>` or an
/// endpoint `Location` it writes is not an absolute URI reference, or when two
/// `ArtifactResolutionService` endpoints share an index. Also returns [`SamlError::Invalid`] for an
/// incomplete organization, an invalid XML Schema language tag, a non-`mailto:`
/// email URI, a non-absolute organization or error URI, or text XML cannot carry,
/// and for an entity attribute whose `NameFormat` is not an absolute URI
/// reference, whose [`crate::AttributeNameFormat::Basic`] name is not an XML
/// name, or whose text XML cannot carry.
/// Returns [`SamlError::Invalid`] for a scope with invalid XML text, a literal
/// scope with uppercase ASCII letters, or an empty certificate.
/// Returns [`SamlError::Base64`] for malformed base64 in a certificate.
pub fn generate_idp_metadata(cfg: &IdpMetadataInput) -> Result<String, SamlError> {
    if cfg.single_sign_on_service.is_empty() {
        return Err(SamlError::MissingMetadata(
            "SingleSignOnService".to_string(),
        ));
    }
    generate_entity_descriptor(
        &cfg.entity_id,
        cfg.lifetime,
        cfg.organization.as_ref(),
        &cfg.contacts,
        cfg.error_url.as_deref(),
        &cfg.entity_attributes,
        |w| write_idp_role(w, cfg),
    )
}

fn write_idp_role(w: &mut MetadataWriter, cfg: &IdpMetadataInput) -> Result<(), SamlError> {
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
    super::scope::write_scopes(w, &cfg.scopes)?;
    write_key_descriptors(w, &cfg.signing_certs, &cfg.encrypt_certs)?;
    write_artifact_resolution_service(w, &cfg.artifact_resolution_service)?;
    write_endpoints(w, "SingleLogoutService", &cfg.single_logout_service)?;
    write_endpoints(w, "ManageNameIDService", &cfg.manage_name_id_service)?;
    write_name_id_formats(w, &cfg.name_id_format)?;
    write_endpoints(w, "SingleSignOnService", &cfg.single_sign_on_service)?;
    w.end("IDPSSODescriptor");
    Ok(())
}

#[cfg(test)]
mod tests;
