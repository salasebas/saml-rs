use crate::browser::{AcsEndpoint, SsoEndpoint};
use crate::config::{EntityId, IdpConfig, SpConfig};
use crate::config::{NameIdFormat, SpValidationPolicy};
use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, name_id_format, signature_algorithm,
    transform_algorithm,
};
use crate::error::SamlError;

const PRIVKEY: &str = include_str!("../../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn sp_config_converts_selected_settings() -> Result<(), SamlError> {
    use crate::config::{
        AlgorithmPolicy, AssertionSignaturePolicy, CertificatePem, Credentials,
        DataEncryptionAlgorithm, KeyEncryptionAlgorithm, PrivateKeyPem, ResponseSignaturePolicy,
        SignatureAlgorithm, TransformAlgorithm, X509Credential, XmlPolicy,
    };
    use crate::xml::XmlLimits;

    let limits = XmlLimits {
        max_bytes: 32_768,
        max_depth: 64,
        max_elements: 512,
        max_attributes_per_element: 16,
        max_attribute_value_bytes: 2048,
        max_element_text_bytes: 4096,
    };
    let setting = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .name_id_format(NameIdFormat::EmailAddress)
    .credentials(
        Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new(CERT),
            PrivateKeyPem::new(PRIVKEY),
        )),
    )
    .validation(SpValidationPolicy {
        assertion_signatures: AssertionSignaturePolicy::RequireSigned,
        response_signatures: ResponseSignaturePolicy::RequireSigned,
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
    assert_eq!(setting.private_key.as_deref(), Some(PRIVKEY));
    assert_eq!(setting.signing_cert.as_deref(), Some(CERT));
    assert_eq!(
        setting.name_id_format,
        vec![name_id_format::EMAIL_ADDRESS.to_string()]
    );
    assert!(setting.want_assertions_signed);
    assert!(setting.want_message_signed);
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

#[test]
fn idp_config_converts_entity_id_and_name_id_format() -> Result<(), SamlError> {
    let setting = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .name_id_format(NameIdFormat::Transient)
    .build()?
    .engine
    .setting;

    assert_eq!(
        setting.entity_id.as_deref(),
        Some("https://idp.example.com/metadata")
    );
    assert_eq!(
        setting.name_id_format,
        vec![name_id_format::TRANSIENT.to_string()]
    );
    Ok(())
}
