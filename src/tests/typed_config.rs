use saml_rs::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, name_id_format,
    signature_algorithm, transform_algorithm,
};
use saml_rs::entity::EntitySetting;
use saml_rs::flow::FlowOptions;
use saml_rs::tests::policies_without_crypto::sp_validation_without_crypto;
use saml_rs::{
    AcsEndpoint, CertificatePem, Credentials, DataEncryptionAlgorithm, DigestAlgorithm, EntityId,
    HmacSecret, IdentityProvider, IdpConfig, IdpDescriptor, KeyEncryptionAlgorithm,
    MaskGenerationFunction, MetadataTrustPolicy, NameIdFormat, Passphrase, PrivateKeyPem,
    SamlError, ServiceProvider, SignatureAlgorithm, SpConfig, SpDescriptor, SsoEndpoint,
    TransformAlgorithm, X509Credential,
};

const IDP_METADATA: &str = include_str!("../../tests/fixtures/misc/idpmeta.xml");
const SP_METADATA: &str = include_str!("../../tests/fixtures/misc/spmeta.xml");

#[test]
fn typed_config_private_key_debug_is_redacted() {
    let key = PrivateKeyPem::new("dummy-private-key-for-redaction-test");

    let debug = format!("{key:?}");

    assert!(!debug.contains("dummy-private-key-for-redaction-test"));
    assert!(debug.contains("redacted"));
}

#[test]
fn typed_config_passphrase_debug_is_redacted() {
    let passphrase = Passphrase::new("dummy-passphrase-for-redaction-test");

    let debug = format!("{passphrase:?}");

    assert!(!debug.contains("dummy-passphrase-for-redaction-test"));
    assert!(debug.contains("redacted"));
}

#[test]
fn hmac_secret_debug_is_redacted_where_it_is_carried() -> Result<(), SamlError> {
    const SECRET: &[u8] = b"dummy-hmac-secret-for-debug-test";
    let secret = HmacSecret::try_new(SECRET)?;
    let setting = EntitySetting {
        hmac_secret: Some(secret.clone()),
        ..EntitySetting::default()
    };
    let flow = FlowOptions {
        hmac_secret: Some(&secret),
        ..FlowOptions::default()
    };

    for debug in [
        format!("{secret:?}"),
        format!("{setting:?}"),
        format!("{flow:?}"),
    ] {
        assert!(debug.contains("redacted"), "{debug}");
        assert!(!debug.contains("dummy-hmac-secret"), "{debug}");
        assert!(!debug.contains(&format!("{SECRET:?}")), "{debug}");
    }
    Ok(())
}

#[test]
fn hmac_secret_is_at_least_the_sha1_output_length() {
    assert!(matches!(
        HmacSecret::try_new([0_u8; HmacSecret::MIN_LEN - 1]),
        Err(SamlError::Invalid(_))
    ));
    assert!(HmacSecret::try_new([0_u8; HmacSecret::MIN_LEN]).is_ok());
}

/// The second line of `pem`: base64 of the key or certificate, which no
/// `Debug` output may show.
fn pem_body(pem: &str) -> Result<&str, String> {
    pem.lines()
        .nth(1)
        .ok_or_else(|| "PEM fixture has no body".to_string())
}

#[test]
fn typed_config_credentials_debug_redacts_every_secret() -> Result<(), Box<dyn std::error::Error>> {
    const SIGNING_KEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const SIGNING_CERT: &str =
        include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    const DECRYPTION_KEY: &str =
        include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
    const DECRYPTION_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
    // An unencrypted key loads with any passphrase.
    let credentials = Credentials::default()
        .with_signing_credential(
            X509Credential::new(
                CertificatePem::new(SIGNING_CERT),
                PrivateKeyPem::new(SIGNING_KEY),
            )
            .with_passphrase(Passphrase::new(
                "dummy-signing-pass-for-credentials-debug-test",
            )),
        )
        .with_decryption_credential(
            X509Credential::new(
                CertificatePem::new(DECRYPTION_CERT),
                PrivateKeyPem::new(DECRYPTION_KEY),
            )
            .with_passphrase(Passphrase::new(
                "dummy-decryption-pass-for-credentials-debug-test",
            )),
        );
    let material = [
        pem_body(SIGNING_KEY)?,
        pem_body(SIGNING_CERT)?,
        pem_body(DECRYPTION_KEY)?,
        pem_body(DECRYPTION_CERT)?,
    ];

    let sp = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .credentials(credentials.clone())
    .validation(sp_validation_without_crypto())
    .build()?;
    let idp = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .credentials(credentials.clone())
    .build()?;

    let service_provider = ServiceProvider::new(sp.clone());
    let identity_provider = IdentityProvider::new(idp.clone());

    for debug in [
        format!("{credentials:?}"),
        format!("{sp:?}"),
        format!("{idp:?}"),
        format!("{service_provider:?}"),
        format!("{identity_provider:?}"),
    ] {
        assert!(debug.contains("redacted"), "{debug}");
        assert!(!debug.contains("for-credentials-debug-test"), "{debug}");
        for body in material {
            assert!(!debug.contains(body), "{debug}");
        }
    }
    Ok(())
}

#[test]
fn typed_config_certificate_debug_does_not_dump_pem() {
    let certificate = CertificatePem::new("dummy-certificate-for-redaction-test");

    let debug = format!("{certificate:?}");

    assert!(!debug.contains("dummy-certificate-for-redaction-test"));
    assert!(debug.contains("CertificatePem"));
}

#[test]
fn typed_config_entity_setting_debug_redacts_credential_material() {
    let setting = EntitySetting {
        private_key: Some("dummy-private-key-for-entity-debug-test".to_string()),
        private_key_pass: Some("dummy-private-key-pass-for-entity-debug-test".to_string()),
        signing_cert: Some("dummy-signing-cert-for-entity-debug-test".to_string()),
        encrypt_cert: Some("dummy-encrypt-cert-for-entity-debug-test".to_string()),
        enc_private_key: Some("dummy-enc-private-key-for-entity-debug-test".to_string()),
        enc_private_key_pass: Some("dummy-enc-pass-for-entity-debug-test".to_string()),
        ..EntitySetting::default()
    };

    let debug = format!("{setting:?}");

    assert!(debug.contains("private_key"));
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("dummy-private-key-for-entity-debug-test"));
    assert!(!debug.contains("dummy-private-key-pass-for-entity-debug-test"));
    assert!(!debug.contains("dummy-signing-cert-for-entity-debug-test"));
    assert!(!debug.contains("dummy-encrypt-cert-for-entity-debug-test"));
    assert!(!debug.contains("dummy-enc-private-key-for-entity-debug-test"));
    assert!(!debug.contains("dummy-enc-pass-for-entity-debug-test"));
}

#[test]
fn typed_config_algorithm_enums_return_existing_uri_constants() {
    assert_eq!(
        SignatureAlgorithm::RsaSha256.as_uri(),
        signature_algorithm::RSA_SHA256
    );
    assert_eq!(
        SignatureAlgorithm::RsaSha384.as_uri(),
        signature_algorithm::RSA_SHA384
    );
    assert_eq!(
        SignatureAlgorithm::RsaSha512.as_uri(),
        signature_algorithm::RSA_SHA512
    );
    assert_eq!(DigestAlgorithm::Sha256.as_uri(), digest_algorithm::SHA256);
    assert_eq!(DigestAlgorithm::Sha384.as_uri(), digest_algorithm::SHA384);
    assert_eq!(DigestAlgorithm::Sha1.as_uri(), digest_algorithm::SHA1);
    assert_eq!(
        DataEncryptionAlgorithm::Aes256Cbc.as_uri(),
        data_encryption_algorithm::AES_256
    );
    assert_eq!(
        DataEncryptionAlgorithm::Aes256Gcm.as_uri(),
        "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    );
    assert_eq!(
        KeyEncryptionAlgorithm::RsaOaep {
            digest: DigestAlgorithm::Sha256,
            mgf: MaskGenerationFunction::Mgf1Sha256,
        }
        .as_uri(),
        "http://www.w3.org/2009/xmlenc11#rsa-oaep"
    );
    for (mgf, uri) in [
        (
            MaskGenerationFunction::Mgf1Sha256,
            "http://www.w3.org/2009/xmlenc11#mgf1sha256",
        ),
        (
            MaskGenerationFunction::Mgf1Sha384,
            "http://www.w3.org/2009/xmlenc11#mgf1sha384",
        ),
        (
            MaskGenerationFunction::Mgf1Sha512,
            "http://www.w3.org/2009/xmlenc11#mgf1sha512",
        ),
    ] {
        assert_eq!(mgf.as_uri(), uri);
    }
    assert_eq!(
        DataEncryptionAlgorithm::TripleDesCbc.as_uri(),
        data_encryption_algorithm::TRIPLE_DES
    );
    assert_eq!(
        KeyEncryptionAlgorithm::RsaOaepMgf1p.as_uri(),
        key_encryption_algorithm::RSA_OAEP_MGF1P
    );
    assert_eq!(
        KeyEncryptionAlgorithm::Rsa15.as_uri(),
        key_encryption_algorithm::RSA_1_5
    );
    assert_eq!(
        TransformAlgorithm::EnvelopedSignature.as_uri(),
        transform_algorithm::ENVELOPED_SIGNATURE
    );
    assert_eq!(
        TransformAlgorithm::ExclusiveCanonicalization.as_uri(),
        transform_algorithm::EXC_C14N
    );
}

#[test]
fn typed_config_name_id_formats_return_existing_uri_constants() {
    assert_eq!(
        NameIdFormat::EmailAddress.as_uri(),
        name_id_format::EMAIL_ADDRESS
    );
    assert_eq!(
        NameIdFormat::Persistent.as_uri(),
        name_id_format::PERSISTENT
    );
    assert_eq!(NameIdFormat::Transient.as_uri(), name_id_format::TRANSIENT);
    assert_eq!(NameIdFormat::Entity.as_uri(), name_id_format::ENTITY);
    assert_eq!(
        NameIdFormat::Unspecified.as_uri(),
        name_id_format::UNSPECIFIED
    );
    assert_eq!(NameIdFormat::Kerberos.as_uri(), name_id_format::KERBEROS);
    assert_eq!(
        NameIdFormat::WindowsDomainQualifiedName.as_uri(),
        name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME
    );
    assert_eq!(
        NameIdFormat::X509SubjectName.as_uri(),
        name_id_format::X509_SUBJECT_NAME
    );
}

#[test]
fn typed_config_idp_descriptor_accepts_expected_unsigned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IDP_METADATA,
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    assert_eq!(
        descriptor.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert!(!descriptor.signed_metadata_xml().is_some());
    Ok(())
}

#[test]
fn typed_config_idp_descriptor_rejects_unexpected_entity_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://unexpected.example.com/metadata")?,
        IDP_METADATA,
        MetadataTrustPolicy::AllowUnsigned,
    );

    assert!(
        matches!(
            &result,
            Err(SamlError::Invalid(message))
                if message.contains("metadata entityID")
                    && message.contains("https://unexpected.example.com/metadata")
                    && message.contains("https://idp.example.com/metadata")
        ),
        "unexpected entity ID error: {result:?}"
    );
    Ok(())
}

#[test]
fn typed_config_sp_descriptor_accepts_expected_unsigned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.org/metadata")?,
        SP_METADATA,
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    assert_eq!(
        descriptor.entity_id().as_str(),
        "https://sp.example.org/metadata"
    );
    assert!(!descriptor.signed_metadata_xml().is_some());
    assert_eq!(descriptor.signed_metadata_xml(), None);
    Ok(())
}

#[test]
fn typed_config_descriptors_import_a_peer_entity_id_that_is_not_a_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata = IDP_METADATA.replace("https://idp.example.com/metadata", "idp.example.com");
    let sp_metadata = SP_METADATA.replace("https://sp.example.org/metadata", "sp.example.org");

    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("idp.example.com")?,
        &idp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("sp.example.org")?,
        &sp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    assert_eq!(idp.entity_id().as_str(), "idp.example.com");
    assert_eq!(sp.entity_id().as_str(), "sp.example.org");
    Ok(())
}

#[test]
fn typed_config_descriptors_return_the_imported_metadata_xml_unchanged(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata = IDP_METADATA.replace('\n', "\r\n");
    let sp_metadata = SP_METADATA.replace('\n', "\r\n");

    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.org/metadata")?,
        &sp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    assert_eq!(idp.metadata_xml(), idp_metadata);
    assert_eq!(sp.metadata_xml(), sp_metadata);
    Ok(())
}

#[test]
fn typed_config_pinned_certificate_trust_does_not_accept_unsigned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IDP_METADATA,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: &[],
        },
    );

    assert!(
        result.is_err(),
        "empty pinned certificate trust must not accept unsigned metadata"
    );
    Ok(())
}
