use crate::browser::{AcsEndpoint, SsoEndpoint};
use crate::config::{EntityId, IdpConfig, SpConfig};
#[cfg(crypto)]
use crate::config::{IdpValidationPolicy, NameIdFormat, SpValidationPolicy};
#[cfg(crypto)]
use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, name_id_format, signature_algorithm,
    transform_algorithm,
};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::tests::policies_without_crypto::{
    idp_validation_without_crypto, sp_validation_without_crypto,
};

#[test]
fn unsigned_logout_clears_the_raw_signature_requirements() -> Result<(), SamlError> {
    let raw = EntitySetting::default();
    assert!(raw.want_logout_request_signed);
    assert!(raw.want_logout_response_signed);

    let sp = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(sp_validation_without_crypto())
    .build()?
    .engine
    .setting;
    assert!(!sp.want_logout_request_signed);
    assert!(!sp.want_logout_response_signed);

    let idp = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .validation(idp_validation_without_crypto())
    .build()?
    .engine
    .setting;
    assert!(!idp.want_logout_request_signed);
    assert!(!idp.want_logout_response_signed);
    Ok(())
}

#[cfg(crypto)]
#[test]
fn sp_config_converts_selected_settings() -> Result<(), SamlError> {
    use crate::config::{
        AlgorithmPolicy, AssertionSignaturePolicy, AuthnRequestSigningPolicy, CertificatePem,
        Credentials, DataEncryptionAlgorithm, KeyEncryptionAlgorithm, PrivateKeyPem,
        ResponseSignaturePolicy, SignatureAlgorithm, TransformAlgorithm, X509Credential, XmlPolicy,
    };
    use crate::xml::XmlLimits;

    let limits = XmlLimits {
        max_bytes: 32_768,
        max_depth: 64,
        max_nodes: 512,
        max_attributes_per_element: 16,
        max_attribute_value_bytes: 2048,
        max_text_bytes: 4096,
    };
    let setting = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .name_id_format(NameIdFormat::EmailAddress)
    .credentials(
        Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new("dummy-signing-certificate-for-conversion-test"),
            PrivateKeyPem::new("dummy-private-key-for-conversion-test"),
        )),
    )
    .validation(SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        responses: ResponseSignaturePolicy::RequireSigned,
        authn_requests: AuthnRequestSigningPolicy::Sign,
        ..SpValidationPolicy::default()
    })
    .xml(XmlPolicy {
        limits,
        ..XmlPolicy::default()
    })
    .algorithms(AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha512,
        data_encryption: DataEncryptionAlgorithm::Aes128Cbc,
        key_encryption: KeyEncryptionAlgorithm::Rsa15,
        signed_reference_transforms: vec![TransformAlgorithm::ExclusiveCanonicalization],
    })
    .build()?
    .engine
    .setting;

    assert_eq!(
        setting.entity_id.as_deref(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(
        setting.private_key.as_deref(),
        Some("dummy-private-key-for-conversion-test")
    );
    assert_eq!(
        setting.signing_cert.as_deref(),
        Some("dummy-signing-certificate-for-conversion-test")
    );
    assert_eq!(
        setting.name_id_format,
        vec![name_id_format::EMAIL_ADDRESS.to_string()]
    );
    assert!(setting.want_assertions_signed);
    assert!(setting.want_message_signed);
    assert!(setting.authn_requests_signed);
    assert_eq!(setting.xml_limits, limits);
    assert_eq!(
        setting.request_signature_algorithm,
        signature_algorithm::RSA_SHA512
    );
    assert_eq!(
        setting.data_encryption_algorithm,
        data_encryption_algorithm::AES_128
    );
    assert_eq!(
        setting.key_encryption_algorithm,
        key_encryption_algorithm::RSA_1_5
    );
    assert_eq!(
        setting.transformation_algorithms,
        vec![transform_algorithm::EXC_C14N.to_string()]
    );
    Ok(())
}

#[cfg(crypto)]
#[test]
fn idp_config_converts_authn_request_policy() -> Result<(), SamlError> {
    use crate::config::AuthnRequestValidationPolicy;

    let setting = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .name_id_format(NameIdFormat::Transient)
    .validation(IdpValidationPolicy {
        authn_requests: AuthnRequestValidationPolicy::RequireSigned,
        ..IdpValidationPolicy::default()
    })
    .build()?
    .engine
    .setting;

    assert_eq!(
        setting.entity_id.as_deref(),
        Some("https://idp.example.com/metadata")
    );
    assert!(setting.want_authn_requests_signed);
    assert_eq!(
        setting.name_id_format,
        vec![name_id_format::TRANSIENT.to_string()]
    );
    Ok(())
}
