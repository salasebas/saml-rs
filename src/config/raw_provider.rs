//! Typed configs to the raw metadata configs and providers the typed API runs on.

use crate::error::SamlError;
use crate::idp::IdentityProvider;
use crate::metadata::{
    ArtifactResolutionEndpoint, IdpMetadataConfig as RawIdpMetadataConfig,
    SpMetadataConfig as RawSpMetadataConfig,
};
use crate::sp::ServiceProvider;

use super::algorithms::name_id_format_uris;
use super::builders::{IdpConfig, SpConfig};
use super::credentials::Credentials;
use super::descriptors::ManageNameIdService;
use super::policies::{
    AssertionSignaturePolicy, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy,
};

impl SpConfig {
    pub(crate) fn to_service_provider(&self) -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(&raw_sp_metadata_config(self), self.entity_setting())
    }
}

impl IdpConfig {
    pub(crate) fn to_identity_provider(&self) -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(&raw_idp_metadata_config(self), self.entity_setting())
    }
}

fn raw_sp_metadata_config(config: &SpConfig) -> RawSpMetadataConfig {
    let metadata = config.metadata();
    RawSpMetadataConfig {
        entity_id: config.entity_id().as_str().to_string(),
        signing_certs: signing_certificates(config.credentials()),
        encrypt_certs: encryption_certificates(config.credentials()),
        authn_requests_signed: matches!(
            config.validation().authn_requests,
            AuthnRequestSigningPolicy::Sign
        ),
        want_assertions_signed: matches!(
            config.validation().assertions,
            AssertionSignaturePolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(metadata.name_id_format()),
        single_logout_service: metadata
            .single_logout_service()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        assertion_consumer_service: metadata
            .assertion_consumer_service()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        manage_name_id_service: metadata
            .manage_name_id_service()
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        elements_order: metadata.elements_order().map(<[String]>::to_vec),
        lifetime: metadata.lifetime(),
        organization: metadata.organization().cloned(),
        contacts: metadata.contacts().to_vec(),
        error_url: metadata.error_url().map(str::to_string),
    }
}

fn raw_idp_metadata_config(config: &IdpConfig) -> RawIdpMetadataConfig {
    let metadata = config.metadata();
    RawIdpMetadataConfig {
        entity_id: config.entity_id().as_str().to_string(),
        signing_certs: signing_certificates(config.credentials()),
        encrypt_certs: encryption_certificates(config.credentials()),
        want_authn_requests_signed: matches!(
            config.validation().authn_requests,
            AuthnRequestValidationPolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(metadata.name_id_format()),
        single_sign_on_service: metadata
            .single_sign_on_service()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        single_logout_service: metadata
            .single_logout_service()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        artifact_resolution_service: metadata
            .artifact_resolution_service()
            .iter()
            .map(|service| ArtifactResolutionEndpoint {
                index: service.index(),
                location: service.location().as_str().to_string(),
            })
            .collect(),
        manage_name_id_service: metadata
            .manage_name_id_service()
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        elements_order: metadata.elements_order().map(<[String]>::to_vec),
        lifetime: metadata.lifetime(),
        organization: metadata.organization().cloned(),
        contacts: metadata.contacts().to_vec(),
        error_url: metadata.error_url().map(str::to_string),
    }
}

fn signing_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .signing_certificate()
        .into_iter()
        .chain(credentials.additional_signing_certificates())
        .map(|certificate| certificate.as_str().to_string())
        .collect()
}

fn encryption_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .decryption()
        .into_iter()
        .chain(credentials.additional_decryption_keys())
        .map(|credential| credential.certificate.as_str().to_string())
        .collect()
}
