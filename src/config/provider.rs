//! Typed config builders to the metadata generator input and the internal providers the typed API runs on.

use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::error::SamlError;
use crate::idp;
use crate::metadata::{IdpMetadataInput, SpMetadataInput};
use crate::sp;

use super::algorithms::name_id_format_uris;
use super::builders::{IdpConfigBuilder, SpConfigBuilder};
use super::credentials::{Credentials, X509Credential};
use super::descriptors::ManageNameIdService;
use super::policies::{
    assertion_signature_required, authn_request_signature_required, authn_request_signing_enabled,
};

impl SpConfigBuilder {
    pub(super) fn engine(&self) -> Result<sp::Engine, SamlError> {
        sp::Engine::from_config(&sp_metadata_input(self), self.entity_setting())
    }
}

impl IdpConfigBuilder {
    pub(super) fn engine(&self) -> Result<idp::Engine, SamlError> {
        idp::Engine::from_config(&idp_metadata_input(self), self.entity_setting())
    }
}

fn sp_metadata_input(config: &SpConfigBuilder) -> SpMetadataInput {
    let metadata = &config.metadata;
    SpMetadataInput {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: signing_certificates(&config.credentials),
        encrypt_certs: encryption_certificates(&config.credentials),
        authn_requests_signed: authn_request_signing_enabled(
            config.validation.authn_request_signing,
        ),
        want_assertions_signed: assertion_signature_required(
            config.validation.assertion_signatures,
        ),
        name_id_format: name_id_format_uris(metadata.name_id_formats()),
        single_logout_service: metadata
            .slo_endpoints()
            .iter()
            .map(SloEndpoint::to_raw)
            .collect(),
        assertion_consumer_service: metadata
            .acs_endpoints()
            .iter()
            .map(AcsEndpoint::to_raw)
            .collect(),
        manage_name_id_service: metadata
            .manage_name_id_services()
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        lifetime: metadata.lifetime(),
        organization: metadata.organization().cloned(),
        contacts: metadata.contacts().to_vec(),
        error_url: metadata.error_url().map(str::to_string),
        entity_attributes: metadata.entity_attributes().to_vec(),
    }
}

fn idp_metadata_input(config: &IdpConfigBuilder) -> IdpMetadataInput {
    let metadata = &config.metadata;
    IdpMetadataInput {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: signing_certificates(&config.credentials),
        encrypt_certs: encryption_certificates(&config.credentials),
        want_authn_requests_signed: authn_request_signature_required(
            config.validation.authn_request_signatures,
        ),
        name_id_format: name_id_format_uris(metadata.name_id_formats()),
        single_sign_on_service: metadata
            .sso_endpoints()
            .iter()
            .map(SsoEndpoint::to_raw)
            .collect(),
        single_logout_service: metadata
            .slo_endpoints()
            .iter()
            .map(SloEndpoint::to_raw)
            .collect(),
        artifact_resolution_service: metadata.artifact_resolution_services().to_vec(),
        manage_name_id_service: metadata
            .manage_name_id_services()
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        lifetime: metadata.lifetime(),
        organization: metadata.organization().cloned(),
        contacts: metadata.contacts().to_vec(),
        error_url: metadata.error_url().map(str::to_string),
        entity_attributes: metadata.entity_attributes().to_vec(),
        scopes: metadata.scopes().to_vec(),
    }
}

fn signing_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .signing_credential()
        .map(X509Credential::certificate)
        .into_iter()
        .chain(credentials.additional_signing_certificates())
        .map(|certificate| certificate.as_str().to_string())
        .collect()
}

fn encryption_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .decryption_credentials()
        .iter()
        .map(|credential| credential.certificate().as_str().to_string())
        .collect()
}
