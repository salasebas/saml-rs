mod common;
#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

use common::signing_credentials;
use policies_without_crypto::sp_validation_without_crypto;

use std::{str::FromStr, time::Duration};

use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AuthnRequestSigningPolicy, Credentials, DataEncryptionAlgorithm, DigestAlgorithm, EntityId,
    IdpConfig, KeyEncryptionAlgorithm, MaskGenerationFunction, NameIdCreationPolicy, SamlError,
    SignatureAlgorithm, SignatureConfig, SpConfig, SpValidationPolicy, SsoEndpoint, TemplatePolicy,
    TransformAlgorithm, XmlPolicy, XmlSignatureProfile,
};

#[cfg(crypto)]
#[test]
fn builders_reject_unsupported_xmlenc11_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let mut unsupported_digest = AlgorithmPolicy::default();
    unsupported_digest.key_encryption = KeyEncryptionAlgorithm::RsaOaep {
        digest: DigestAlgorithm::Custom("urn:test:unsupported-oaep-digest".into()),
        mgf: MaskGenerationFunction::Mgf1Sha256,
    };
    let mut algorithms = vec![unsupported_digest];
    if cfg!(any(feature = "crypto-aws-lc", feature = "crypto-fips")) {
        let mut mismatched_mgf = AlgorithmPolicy::default();
        mismatched_mgf.key_encryption = KeyEncryptionAlgorithm::RsaOaep {
            digest: DigestAlgorithm::Sha256,
            mgf: MaskGenerationFunction::Mgf1Sha384,
        };
        algorithms.push(mismatched_mgf);
    }
    for algorithms in algorithms {
        let sp = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .algorithms(algorithms.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .algorithms(algorithms)
        .build();
        assert!(matches!(sp, Err(SamlError::Unsupported(_))), "{sp:?}");
        assert!(matches!(idp, Err(SamlError::Unsupported(_))), "{idp:?}");
    }
    Ok(())
}

#[cfg(not(crypto))]
#[test]
fn protocol_only_builders_accept_any_encryption_algorithm() -> Result<(), Box<dyn std::error::Error>>
{
    let mut aes128_gcm = AlgorithmPolicy::default();
    aes128_gcm.data_encryption = DataEncryptionAlgorithm::Aes128Gcm;
    let mut aes256_gcm = AlgorithmPolicy::default();
    aes256_gcm.data_encryption = DataEncryptionAlgorithm::Aes256Gcm;
    let mut rsa_oaep = AlgorithmPolicy::default();
    rsa_oaep.key_encryption = KeyEncryptionAlgorithm::RsaOaep {
        digest: DigestAlgorithm::Custom("urn:test:unsupported-oaep-digest".into()),
        mgf: MaskGenerationFunction::Mgf1Sha256,
    };
    for algorithms in [aes128_gcm, aes256_gcm, rsa_oaep] {
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .algorithms(algorithms.clone())
        .build()?;
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .algorithms(algorithms)
        .build()?;
    }
    Ok(())
}

#[cfg(crypto)]
fn assert_missing_key(result: Result<impl Sized, SamlError>, field: &str) {
    assert!(matches!(
        result,
        Err(SamlError::MissingKey(message)) if message == field
    ));
}

#[test]
fn idp_config_defaults_issuance_lifetime_to_five_minutes() -> Result<(), Box<dyn std::error::Error>>
{
    let config = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .build()?;

    assert_eq!(config.issuance_lifetime(), Duration::from_secs(300));
    Ok(())
}

#[cfg(crypto)]
#[test]
fn idp_builder_sets_issuance_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let config = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .issuance_lifetime(Duration::from_secs(600))
    .build()?;

    assert_eq!(config.issuance_lifetime(), Duration::from_secs(600));
    Ok(())
}

#[test]
fn idp_config_rejects_zero_issuance_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .issuance_lifetime(Duration::ZERO)
    .build();

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "IdP issuance lifetime must be greater than zero"
    ));
    Ok(())
}

#[test]
fn idp_config_rejects_unrepresentable_issuance_lifetime() -> Result<(), Box<dyn std::error::Error>>
{
    let result = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .issuance_lifetime(Duration::MAX)
    .build();

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "IdP issuance lifetime must fit in time::Duration (at most i64::MAX seconds plus 999,999,999 nanoseconds)"
    ));
    Ok(())
}

#[cfg(crypto)]
#[test]
fn builders_start_on_recommended() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AudienceValidationPolicy, AuthnRequestValidationPolicy, IdpValidationPolicy,
        ResponseSignaturePolicy,
    };

    let sp = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .build()?;
    let idp = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .build()?;

    let (sp, idp) = (sp.validation(), idp.validation());
    assert_eq!(sp, &SpValidationPolicy::default());
    assert_eq!(idp, &IdpValidationPolicy::default());
    assert_eq!(sp.assertions, AssertionSignaturePolicy::AllowUnsigned);
    assert_eq!(
        sp.responses,
        ResponseSignaturePolicy::RequireForEncryptedCbc
    );
    assert_eq!(sp.authn_requests, AuthnRequestSigningPolicy::DoNotSign);
    assert_eq!(
        sp.audience,
        AudienceValidationPolicy::EvaluatePresentRestrictions
    );
    assert_eq!(sp.name_id_creation, NameIdCreationPolicy::DoNotAllowCreate);
    assert_eq!(
        sp.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    assert_eq!(
        idp.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsigned
    );
    assert_eq!(
        idp.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    Ok(())
}

#[test]
fn recommended_hardenings_stay_independent() {
    let mut assertion_signature = SpValidationPolicy::default();
    assertion_signature.assertions = AssertionSignaturePolicy::RequireSigned;
    assert_eq!(
        assertion_signature.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    let mut rsa_sha2 = SpValidationPolicy::default();
    rsa_sha2.xml_signatures = XmlSignatureProfile::StrictRsaSha2;
    assert_eq!(rsa_sha2.assertions, AssertionSignaturePolicy::AllowUnsigned);
}

#[test]
fn field_defaults_match_the_role_policy() {
    let sp = SpValidationPolicy::default();
    assert_eq!(AssertionSignaturePolicy::default(), sp.assertions);
    assert_eq!(AuthnRequestSigningPolicy::default(), sp.authn_requests);
    assert_eq!(NameIdCreationPolicy::default(), sp.name_id_creation);
}

#[test]
fn custom_algorithm_variants_keep_simple_names() {
    let variants = [
        format!("{:?}", SignatureAlgorithm::Custom("urn:test".into())),
        format!("{:?}", DigestAlgorithm::Custom("urn:test".into())),
        format!("{:?}", DataEncryptionAlgorithm::Custom("urn:test".into())),
        format!("{:?}", KeyEncryptionAlgorithm::Custom("urn:test".into())),
        format!("{:?}", TransformAlgorithm::Custom("urn:test".into())),
    ];

    assert!(variants
        .iter()
        .all(|variant| variant.starts_with("Custom(")));
}

#[cfg(crypto)]
#[test]
fn sp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let mut algorithms = AlgorithmPolicy::default();
    algorithms.signature = SignatureAlgorithm::RsaSha512;
    algorithms.data_encryption = DataEncryptionAlgorithm::Aes128Cbc;
    algorithms.key_encryption = KeyEncryptionAlgorithm::RsaOaepMgf1p;
    algorithms.signed_reference_transforms = vec![TransformAlgorithm::ExclusiveCanonicalization];
    let mut xml = XmlPolicy::default();
    xml.redirect_inflate_max_bytes = 64 * 1024;
    let mut templates = TemplatePolicy::default();
    templates.tag_prefix_protocol = "p".to_string();

    let config = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .credentials(signing_credentials())
    .algorithms(algorithms.clone())
    .xml(xml)
    .templates(templates.clone())
    .build()?;

    assert_eq!(config.algorithms(), &algorithms);
    assert_eq!(config.xml(), &xml);
    assert_eq!(
        config.templates().tag_prefix_protocol,
        templates.tag_prefix_protocol
    );
    Ok(())
}

#[cfg(crypto)]
#[test]
fn idp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let mut algorithms = AlgorithmPolicy::default();
    algorithms.signature = SignatureAlgorithm::RsaSha384;
    algorithms.data_encryption = DataEncryptionAlgorithm::Aes256Cbc;
    algorithms.key_encryption = KeyEncryptionAlgorithm::RsaOaepMgf1p;
    algorithms.signed_reference_transforms = vec![TransformAlgorithm::EnvelopedSignature];
    let mut xml = XmlPolicy::default();
    xml.redirect_inflate_max_bytes = 128 * 1024;
    let mut templates = TemplatePolicy::default();
    templates.tag_prefix_assertion = "a".to_string();

    let config = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .algorithms(algorithms.clone())
    .xml(xml)
    .templates(templates.clone())
    .build()?;

    assert_eq!(config.algorithms(), &algorithms);
    assert_eq!(config.xml(), &xml);
    assert_eq!(
        config.templates().tag_prefix_assertion,
        templates.tag_prefix_assertion
    );
    Ok(())
}

fn entity_ids_that_are_not_a_uri_of_at_most_1024_characters() -> [String; 4] {
    [
        "not a uri".into(),
        "/metadata".into(),
        " https://sp.example.com/metadata\n".into(),
        format!("https://sp.example.com/{}", "a".repeat(1002)),
    ]
}

#[test]
fn entity_id_constructors_reject_only_a_value_without_a_non_whitespace_character(
) -> Result<(), Box<dyn std::error::Error>> {
    for value in ["", " ", " \t\n"] {
        assert!(
            matches!(EntityId::try_new(value), Err(SamlError::Invalid(_))),
            "{value:?}"
        );
        assert!(
            matches!(EntityId::from_str(value), Err(SamlError::Invalid(_))),
            "{value:?}"
        );
        assert!(
            matches!(EntityId::try_from(value), Err(SamlError::Invalid(_))),
            "{value:?}"
        );
        assert!(
            matches!(
                EntityId::try_from(value.to_string()),
                Err(SamlError::Invalid(_))
            ),
            "{value:?}"
        );
    }
    for value in entity_ids_that_are_not_a_uri_of_at_most_1024_characters()
        .into_iter()
        .chain([
            "https://sp.example.com/metadata".to_string(),
            "urn:example:sp".into(),
            format!("https://sp.example.com/{}", "a".repeat(1001)),
            format!("https://sp.example.com/{}", "\u{e9}".repeat(1001)),
        ])
    {
        assert_eq!(EntityId::try_new(value.clone())?.as_str(), value);
        assert_eq!(EntityId::from_str(&value)?.as_str(), value);
        assert_eq!(EntityId::try_from(value.as_str())?.as_str(), value);
        assert_eq!(EntityId::try_from(value.clone())?.as_str(), value);
    }
    Ok(())
}

#[test]
fn config_builders_reject_an_entity_id_that_is_not_a_uri_of_at_most_1024_characters(
) -> Result<(), Box<dyn std::error::Error>> {
    for value in entity_ids_that_are_not_a_uri_of_at_most_1024_characters() {
        let entity_id = EntityId::try_new(value.clone())?;
        let sp = SpConfig::builder(
            entity_id.clone(),
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(signing_credentials())
        .build();
        let idp = IdpConfig::builder(entity_id, SsoEndpoint::post("https://idp.example.com/sso")?)
            .credentials(signing_credentials())
            .build();

        assert!(matches!(sp, Err(SamlError::Invalid(_))), "{value}");
        assert!(matches!(idp, Err(SamlError::Invalid(_))), "{value}");
    }
    Ok(())
}

#[test]
fn sp_builder_rejects_two_acs_endpoints_with_the_same_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?.with_index(1),
    )
    .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs-2")?.with_index(1))
    .validation(sp_validation_without_crypto())
    .build();

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message)) if message == "duplicate AssertionConsumerService index 1"
    ));
    Ok(())
}

#[test]
fn config_builders_reject_a_tag_prefix_that_is_not_an_ncname(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut protocol_prefix = TemplatePolicy::default();
    protocol_prefix.tag_prefix_protocol = "saml:p".into();
    let mut signature_prefix = TemplatePolicy::default();
    let mut signature_config = SignatureConfig::default();
    signature_config.prefix = "ds:p".into();
    signature_prefix.signature_config = Some(signature_config);
    for (templates, expected) in [
        (protocol_prefix, "protocol tag prefix must be an XML NCName"),
        (
            signature_prefix,
            "SignatureConfig.prefix XML prefix must be an XML NCName",
        ),
    ] {
        let sp = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .templates(templates.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .templates(templates)
        .build();

        assert!(
            matches!(&sp, Err(SamlError::Invalid(message)) if message == expected),
            "{sp:?}"
        );
        assert!(
            matches!(&idp, Err(SamlError::Invalid(message)) if message == expected),
            "{idp:?}"
        );
    }
    Ok(())
}

#[cfg(crypto)]
#[test]
fn config_builders_reject_a_credential_that_cannot_be_used(
) -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{CertificatePem, PrivateKeyPem, X509Credential};

    const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    const OTHER_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
    const OTHER_CERT: &str = include_str!("fixtures/key/idp/cert.cer");
    let pair = |certificate: &str, key: &str| {
        X509Credential::new(CertificatePem::new(certificate), PrivateKeyPem::new(key))
    };
    let signing = |credential| Credentials::default().with_signing_credential(credential);
    let with_bag_attributes = format!("Bag Attributes\n    localKeyID: 01 00 00 00\n{CERT}");
    let cases = [
        (
            signing(pair(OTHER_CERT, KEY)),
            "signing credential: the private key does not match the certificate",
        ),
        (
            signing(pair(CERT, "not a private key")),
            "signing credential: the private key does not load",
        ),
        (
            signing(pair(CERT, CERT)),
            "signing credential: the private key PEM holds only a public key",
        ),
        (
            signing(pair("not a certificate", KEY)),
            "signing credential: the certificate does not load",
        ),
        (
            signing(pair(&with_bag_attributes, KEY)),
            "signing credential: the certificate does not load",
        ),
        (
            signing(pair(CERT, KEY))
                .with_additional_signing_certificate(CertificatePem::new("not a certificate")),
            "additional signing certificate at index 0: the certificate does not load",
        ),
        (
            Credentials::default()
                .with_decryption_credential(pair(CERT, KEY))
                .with_decryption_credential(pair(CERT, OTHER_KEY)),
            "decryption credential at index 1: the private key does not match the certificate",
        ),
    ];

    for (credentials, expected) in cases {
        let sp = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(credentials.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(credentials)
        .build();

        assert!(
            matches!(&sp, Err(SamlError::Crypto { message, .. }) if message == expected),
            "{expected}: {sp:?}"
        );
        assert!(
            matches!(&idp, Err(SamlError::Crypto { message, .. }) if message == expected),
            "{expected}: {idp:?}"
        );
    }
    Ok(())
}

#[cfg(crypto)]
#[test]
fn sp_builder_requires_signing_credentials_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::default();
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;
    let result = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(validation)
    .build();

    assert_missing_key(result, "signing_credential");
    Ok(())
}

#[test]
fn sp_builder_without_signature_requirements_needs_no_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(sp_validation_without_crypto())
    .build()?;

    assert_eq!(config.validation(), &sp_validation_without_crypto());
    assert_eq!(config.credentials(), &Credentials::default());
    Ok(())
}

#[cfg(crypto)]
#[test]
fn sp_builder_requires_decryption_key_when_encrypted_assertions_are_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut xml = XmlPolicy::default();
    xml.encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;
    let result = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(sp_validation_without_crypto())
    .xml(xml)
    .build();

    assert_missing_key(result, "decryption_credential");
    Ok(())
}

#[test]
fn xml_encryption_policy_defaults_to_plaintext_assertions() {
    assert_eq!(
        XmlPolicy::default().encryption.assertions,
        AssertionEncryptionPolicy::PlaintextAssertions
    );
}
