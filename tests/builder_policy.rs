//! Compatibility is the legacy permissive preset: the samlify-port behavior kept
//! for a caller leaving the raw API.

use std::{str::FromStr, time::Duration};

use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AudienceValidationPolicy, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy,
    CertificatePem, Credentials, DataEncryptionAlgorithm, DigestAlgorithm, EntityId, IdpConfig,
    IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy, LogoutSignaturePolicy,
    MaskGenerationFunction, NameIdCreationPolicy, PrivateKeyPem, ResponseSignaturePolicy,
    SamlError, SignatureAlgorithm, SignatureConfig, SpConfig, SpValidationPolicy, SsoEndpoint,
    TemplatePolicy, TransformAlgorithm, X509Credential, XmlPolicy, XmlSignatureProfile,
};

use saml_rs::raw::EntitySetting;

#[test]
fn builders_reject_unsupported_xmlenc11_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let mut unsupported_digest = AlgorithmPolicy::default();
    unsupported_digest.key_encryption = KeyEncryptionAlgorithm::RsaOaep {
        digest: DigestAlgorithm::Custom("urn:test:unsupported-oaep-digest".into()),
        mgf: MaskGenerationFunction::Mgf1Sha256,
    };
    let mut algorithms = vec![unsupported_digest];
    if cfg!(any(
        feature = "crypto-aws-lc",
        feature = "crypto-fips",
        not(crypto)
    )) {
        let mut mismatched_mgf = AlgorithmPolicy::default();
        mismatched_mgf.key_encryption = KeyEncryptionAlgorithm::RsaOaep {
            digest: DigestAlgorithm::Sha256,
            mgf: MaskGenerationFunction::Mgf1Sha384,
        };
        algorithms.push(mismatched_mgf);
    }
    if cfg!(not(crypto)) {
        let mut gcm = AlgorithmPolicy::default();
        gcm.data_encryption = DataEncryptionAlgorithm::Aes256Gcm;
        algorithms.push(gcm);
    }
    for algorithms in algorithms {
        let sp = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(SpValidationPolicy::compatibility())
        .algorithms(algorithms.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .validation(IdpValidationPolicy::compatibility())
        .algorithms(algorithms)
        .build();
        assert!(matches!(sp, Err(SamlError::Unsupported(_))), "{sp:?}");
        assert!(matches!(idp, Err(SamlError::Unsupported(_))), "{idp:?}");
    }
    Ok(())
}

fn signing_credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new("test signing certificate"),
        PrivateKeyPem::new("test signing key"),
    ))
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
    .validation(IdpValidationPolicy::compatibility())
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
    assert_eq!(sp, &SpValidationPolicy::recommended());
    assert_eq!(idp, &IdpValidationPolicy::recommended());
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
    assert_eq!(sp.logout, LogoutPolicy::recommended());
    assert_eq!(
        sp.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    assert_eq!(
        idp.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent
    );
    assert_eq!(
        idp.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    Ok(())
}

#[test]
fn compatibility_policy_names_unsigned_choices_explicitly() {
    let sp = SpValidationPolicy::compatibility();
    let idp = IdpValidationPolicy::compatibility();

    assert_eq!(sp.assertions, AssertionSignaturePolicy::AllowUnsigned);
    assert_eq!(
        sp.responses,
        ResponseSignaturePolicy::AllowUnsignedEncryptedCbc
    );
    assert_eq!(sp.authn_requests, AuthnRequestSigningPolicy::DoNotSign);
    assert_eq!(sp.audience, AudienceValidationPolicy::Skip);
    assert_eq!(sp.logout, LogoutPolicy::compatibility());
    assert_eq!(sp.xml_signatures, XmlSignatureProfile::AllowWeakAlgorithms);
    assert_eq!(
        idp.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsigned
    );
    assert_eq!(idp.xml_signatures, XmlSignatureProfile::AllowWeakAlgorithms);
    assert_eq!(idp.logout.requests, LogoutSignaturePolicy::AllowUnsigned);
}

#[test]
fn recommended_hardenings_stay_independent() {
    let mut assertion_signature = SpValidationPolicy::recommended();
    assertion_signature.assertions = AssertionSignaturePolicy::RequireSigned;
    assert_eq!(
        assertion_signature.xml_signatures,
        XmlSignatureProfile::ExcludeWeakAlgorithms
    );
    let mut rsa_sha2 = SpValidationPolicy::recommended();
    rsa_sha2.xml_signatures = XmlSignatureProfile::StrictRsaSha2;
    assert_eq!(rsa_sha2.assertions, AssertionSignaturePolicy::AllowUnsigned);
}

#[test]
fn policy_defaults_are_the_recommended_presets() {
    assert!(!EntitySetting::default().want_message_signed);
    let sp = SpValidationPolicy::recommended();
    let logout = LogoutPolicy::recommended();
    assert_eq!(SpValidationPolicy::default(), sp);
    assert_eq!(
        IdpValidationPolicy::default(),
        IdpValidationPolicy::recommended()
    );
    assert_eq!(LogoutPolicy::default(), logout);
    assert_eq!(AssertionSignaturePolicy::default(), sp.assertions);
    assert_eq!(AuthnRequestSigningPolicy::default(), sp.authn_requests);
    assert_eq!(NameIdCreationPolicy::default(), sp.name_id_creation);
    assert_eq!(LogoutSignaturePolicy::default(), logout.requests);
    assert_eq!(LogoutSignaturePolicy::default(), logout.responses);
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

    assert!(variants.iter().all(|variant| variant.contains("Custom")));
    assert!(variants
        .iter()
        .all(|variant| !variant.contains("Compatibility")));
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
    .validation(SpValidationPolicy::compatibility())
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
        .validation(SpValidationPolicy::compatibility())
        .templates(templates.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .validation(IdpValidationPolicy::compatibility())
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
fn sp_builder_requires_signing_credentials_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::recommended();
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
fn sp_builder_allows_protocol_only_compatibility_without_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(SpValidationPolicy::compatibility())
    .build()?;

    assert_eq!(config.validation(), &SpValidationPolicy::compatibility());
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
    .validation(SpValidationPolicy::compatibility())
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
