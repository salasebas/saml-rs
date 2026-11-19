use crate::entity::EntitySetting;

use super::algorithms::{name_id_format_uris, transform_algorithm_uris, NameIdFormat};
use super::builders::{IdpConfigBuilder, SpConfigBuilder};
use super::credentials::{Credentials, X509Credential};
use super::descriptors::EntityId;
use super::policies::{
    assertion_signature_required, audience_restriction_required, audience_validation_enabled,
    authn_request_signature_required, authn_request_signing_enabled,
    encrypted_cbc_response_signature_required, logout_signature_required, name_id_creation_allowed,
    response_signature_required, verify_present_authn_request_signature, AlgorithmPolicy,
    AssertionEncryptionPolicy, ReceivedEncryptedElements, TemplatePolicy, XmlPolicy,
};

impl SpConfigBuilder {
    pub(super) fn entity_setting(&self) -> EntitySetting {
        let mut setting = common_setting(
            &self.entity_id,
            self.metadata.name_id_formats(),
            &self.credentials,
            &self.algorithms,
            &self.xml,
            &self.templates,
        );
        let validation = &self.validation;
        setting.allow_create = name_id_creation_allowed(validation.name_id_creation);
        setting.authn_requests_signed = authn_request_signing_enabled(validation.authn_requests);
        setting.want_assertions_signed = assertion_signature_required(validation.assertions);
        setting.validate_audience = audience_validation_enabled(validation.audience);
        setting.require_audience_restriction = audience_restriction_required(validation.audience);
        setting.want_message_signed = response_signature_required(validation.responses);
        setting.xml_signatures = validation.xml_signatures;
        setting.want_encrypted_cbc_response_signed =
            encrypted_cbc_response_signature_required(validation.responses);
        setting.want_logout_request_signed = logout_signature_required(validation.logout.requests);
        setting.want_logout_response_signed =
            logout_signature_required(validation.logout.responses);
        setting
    }
}

impl IdpConfigBuilder {
    pub(super) fn entity_setting(&self) -> EntitySetting {
        let mut setting = common_setting(
            &self.entity_id,
            self.metadata.name_id_formats(),
            &self.credentials,
            &self.algorithms,
            &self.xml,
            &self.templates,
        );
        let validation = &self.validation;
        setting.want_authn_requests_signed =
            authn_request_signature_required(validation.authn_requests);
        setting.verify_authn_request_signature_if_present =
            verify_present_authn_request_signature(validation.authn_requests);
        setting.xml_signatures = validation.xml_signatures;
        setting.want_logout_request_signed = logout_signature_required(validation.logout.requests);
        setting.want_logout_response_signed =
            logout_signature_required(validation.logout.responses);
        setting
    }
}

fn common_setting(
    entity_id: &EntityId,
    name_id_format: &[NameIdFormat],
    credentials: &Credentials,
    algorithms: &AlgorithmPolicy,
    xml: &XmlPolicy,
    templates: &TemplatePolicy,
) -> EntitySetting {
    let signing = credentials.signing_credential();
    let (decryption, additional_decryption) = match credentials.decryption_credentials() {
        [first, rest @ ..] => (Some(first), rest),
        [] => (None, &[][..]),
    };
    EntitySetting {
        entity_id: Some(entity_id.as_str().to_string()),
        request_signature_algorithm: algorithms.signature.as_uri().to_string(),
        data_encryption_algorithm: algorithms.data_encryption.as_uri().to_string(),
        key_encryption_algorithm: algorithms.key_encryption.as_uri().to_string(),
        rsa_oaep_parameters: if let super::KeyEncryptionAlgorithm::RsaOaep { digest, mgf } =
            &algorithms.key_encryption
        {
            Some((digest.clone(), *mgf))
        } else {
            None
        },
        message_signing_order: algorithms.message_signing_order,
        is_assertion_encrypted: matches!(
            xml.encryption.assertions,
            AssertionEncryptionPolicy::EncryptAssertions
        ),
        assertion_element_encryption: xml.encryption.assertion_elements(),
        received_encrypted_elements: ReceivedEncryptedElements::DecryptReceived,
        allow_rsa15_key_transport_decryption: xml
            .encryption
            .allows_rsa15_key_transport_decryption(),
        max_decryption_work: xml.encryption.max_decryption_work,
        name_id_format: name_id_format_uris(name_id_format),
        private_key: signing.map(|credential| credential.key().as_str().to_string()),
        private_key_pass: signing
            .and_then(X509Credential::passphrase)
            .map(|passphrase| passphrase.as_str().to_string()),
        signing_cert: signing.map(|credential| credential.certificate().as_str().to_string()),
        hmac_secret: credentials.hmac_secret().cloned(),
        encrypt_cert: decryption.map(|credential| credential.certificate().as_str().to_string()),
        enc_private_key: decryption.map(|credential| credential.key().as_str().to_string()),
        enc_private_key_pass: decryption
            .and_then(X509Credential::passphrase)
            .map(|passphrase| passphrase.as_str().to_string()),
        additional_decryption_keys: additional_decryption.to_vec(),
        redirect_inflate_max_bytes: xml.redirect_inflate_max_bytes,
        xml_limits: xml.limits,
        schema_validator: xml.schema_validator,
        tag_prefix_protocol: templates.tag_prefix_protocol.clone(),
        tag_prefix_assertion: templates.tag_prefix_assertion.clone(),
        tag_prefix_encrypted_assertion: templates.tag_prefix_assertion.clone(),
        login_response_template: templates.login_response_template.clone(),
        login_request_template: templates.login_request_template.clone(),
        logout_request_template: templates.logout_request_template.clone(),
        logout_response_template: templates.logout_response_template.clone(),
        signature_config: templates.signature_config.clone(),
        transformation_algorithms: transform_algorithm_uris(
            &algorithms.signed_reference_transforms,
        ),
        ..EntitySetting::default()
    }
}

#[cfg(test)]
mod tests;
