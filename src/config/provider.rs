//! Typed config builders to the metadata generator input and the internal providers the typed API runs on.

use crate::error::SamlError;
use crate::idp;
#[cfg(crypto)]
use crate::metadata::sign_metadata;
use crate::metadata::{
    generate_idp_metadata, generate_sp_metadata, IdpMetadataInput, SpMetadataInput,
};
use crate::sp;

use super::algorithms::name_id_format_uris;
#[cfg(not(crypto))]
use super::algorithms::SignatureAlgorithm;
use super::builders::{IdpConfigBuilder, SpConfigBuilder};
use super::credentials::{Credentials, X509Credential};
use super::descriptors::ManageNameIdService;
use super::policies::{
    assertion_signature_required, authn_request_signature_required, authn_request_signing_enabled,
    AlgorithmPolicy,
};

impl SpConfigBuilder {
    pub(super) fn engine(&self) -> Result<sp::Engine, SamlError> {
        let metadata_xml = published_metadata(
            generate_sp_metadata(&sp_metadata_input(self))?,
            &self.credentials,
            &self.algorithms,
        )?;
        sp::Engine::from_metadata(&metadata_xml, self.entity_setting())
    }
}

impl IdpConfigBuilder {
    pub(super) fn engine(&self) -> Result<idp::Engine, SamlError> {
        let metadata_xml = published_metadata(
            generate_idp_metadata(&idp_metadata_input(self))?,
            &self.credentials,
            &self.algorithms,
        )?;
        idp::Engine::from_metadata(&metadata_xml, self.entity_setting())
    }
}

fn published_metadata(
    metadata_xml: String,
    credentials: &Credentials,
    algorithms: &AlgorithmPolicy,
) -> Result<String, SamlError> {
    match credentials.metadata_signing_credential() {
        Some(credential) => sign_metadata(&metadata_xml, credential, &algorithms.signature),
        None => Ok(metadata_xml),
    }
}

#[cfg(not(crypto))]
fn sign_metadata(
    _metadata_xml: &str,
    _credential: &X509Credential,
    _algorithm: &SignatureAlgorithm,
) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "metadata signing requires a crypto provider feature".into(),
    ))
}

fn sp_metadata_input(config: &SpConfigBuilder) -> SpMetadataInput {
    let metadata = &config.metadata;
    SpMetadataInput {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: signing_certificates(&config.credentials),
        encrypt_certs: encryption_certificates(&config.credentials),
        authn_requests_signed: authn_request_signing_enabled(config.validation.authn_requests),
        want_assertions_signed: assertion_signature_required(config.validation.assertions),
        name_id_format: name_id_format_uris(metadata.name_id_formats()),
        single_logout_service: metadata
            .slo_endpoints()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        assertion_consumer_service: metadata
            .acs_endpoints()
            .iter()
            .map(|endpoint| endpoint.to_raw())
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
            config.validation.authn_requests,
        ),
        name_id_format: name_id_format_uris(metadata.name_id_formats()),
        single_sign_on_service: metadata
            .sso_endpoints()
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        single_logout_service: metadata
            .slo_endpoints()
            .iter()
            .map(|endpoint| endpoint.to_raw())
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
