use crate::entity::EntitySetting;

use super::algorithms::{name_id_format_uris, transform_algorithm_uris, NameIdFormat};
use super::builders::{IdpConfigBuilder, SpConfigBuilder};
use super::credentials::{Credentials, X509Credential};
use super::descriptors::EntityId;
use super::policies::{
    assertion_signature_required, audience_restriction_required,
    encrypted_cbc_response_signature_required, name_id_creation_allowed,
    response_signature_required, AlgorithmPolicy, TemplatePolicy, XmlPolicy,
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
        setting.want_assertions_signed = assertion_signature_required(validation.assertions);
        setting.require_audience_restriction = audience_restriction_required(validation.audience);
        setting.want_message_signed = response_signature_required(validation.responses);
        setting.xml_signatures = validation.xml_signatures;
        setting.want_encrypted_cbc_response_signed =
            encrypted_cbc_response_signature_required(validation.responses);
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
        setting.xml_signatures = self.validation.xml_signatures;
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
        is_assertion_encrypted: xml.encryption.encrypts_assertions(),
        assertion_element_encryption: xml.encryption.assertion_elements(),
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
        logout_request_template: templates.logout_request_template.clone(),
        logout_response_template: templates.logout_response_template.clone(),
        signature_config: templates.signature_config.clone(),
        transformation_algorithms: transform_algorithm_uris(
            &algorithms.signed_reference_transforms,
        ),
        ..EntitySetting::default()
    }
}

#[cfg(all(test, crypto))]
mod tests;
