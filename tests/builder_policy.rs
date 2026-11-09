//! Compatibility is the legacy permissive preset: the samlify-port behavior kept
//! for a caller leaving the raw API.

use std::{str::FromStr, time::Duration};

use saml_rs::{
    AcsEndpoint, AssertionEncryptionPolicy, AssertionSignaturePolicy, AudienceValidationPolicy,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, Credentials,
    DataEncryptionAlgorithm, DigestAlgorithm, EntityId, EntitySetting, IdpConfig,
    IdpMetadataConfig, IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy,
    LogoutSignaturePolicy, NameIdCreationPolicy, Passphrase, PrivateKeyPem,
    ResponseSignaturePolicy, SamlError, SignatureAlgorithm, SpConfig, SpMetadataConfig,
    SpValidationPolicy, SsoEndpoint, TransformAlgorithm, XmlPolicy, XmlSignatureProfile,
};
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use saml_rs::{AlgorithmPolicy, SloEndpoint, TemplatePolicy, XmlEncryptionPolicy};

fn signing_credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new("test signing key")),
        signing_certificate: Some(CertificatePem::new("test signing certificate")),
        ..Credentials::default()
    }
}

fn assert_missing_metadata(result: Result<impl Sized, SamlError>, field: &str) {
    assert!(matches!(
        result,
        Err(SamlError::MissingMetadata(message)) if message == field
    ));
}

fn assert_missing_key(result: Result<impl Sized, SamlError>, field: &str) {
    assert!(matches!(
        result,
        Err(SamlError::MissingKey(message)) if message == field
    ));
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn sp_builder_and_struct_literal_reach_same_config() -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://sp.example.com/metadata")?;
    let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
    let slo = SloEndpoint::post("https://sp.example.com/slo")?;
    let credentials = signing_credentials();
    let validation = SpValidationPolicy::recommended();

    let builder = SpConfig::builder(entity_id.clone())
        .acs_endpoint(acs.clone())
        .slo_endpoint(slo.clone())
        .name_id_format(saml_rs::NameIdFormat::EmailAddress)
        .credentials(credentials.clone())
        .validation(validation.clone())
        .build()?;
    let literal = SpConfig {
        entity_id,
        metadata: SpMetadataConfig {
            name_id_format: vec![saml_rs::NameIdFormat::EmailAddress],
            single_logout_service: vec![slo],
            assertion_consumer_service: vec![acs],
            manage_name_id_service: Vec::new(),
            elements_order: None,
        },
        credentials,
        validation,
        algorithms: AlgorithmPolicy::default(),
        xml: XmlPolicy::default(),
        templates: Default::default(),
    };
    literal.validate()?;

    assert_eq!(builder.entity_id, literal.entity_id);
    assert_eq!(builder.metadata, literal.metadata);
    assert_eq!(builder.credentials, literal.credentials);
    assert_eq!(builder.validation, literal.validation);
    assert_eq!(builder.algorithms, literal.algorithms);
    assert_eq!(builder.xml, literal.xml);
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn idp_builder_and_struct_literal_reach_same_config() -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://idp.example.com/metadata")?;
    let sso = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let slo = SloEndpoint::post("https://idp.example.com/slo")?;
    let validation = IdpValidationPolicy::recommended();

    let builder = IdpConfig::builder(entity_id.clone())
        .sso_endpoint(sso.clone())
        .slo_endpoint(slo.clone())
        .issuance_lifetime(Duration::from_secs(900))
        .validation(validation.clone())
        .build()?;
    let literal = IdpConfig {
        entity_id,
        metadata: IdpMetadataConfig {
            name_id_format: Vec::new(),
            single_sign_on_service: vec![sso],
            single_logout_service: vec![slo],
            artifact_resolution_service: Vec::new(),
            manage_name_id_service: Vec::new(),
            elements_order: None,
        },
        credentials: Credentials::default(),
        issuance_lifetime: Duration::from_secs(900),
        validation,
        algorithms: AlgorithmPolicy::default(),
        xml: XmlPolicy::default(),
        templates: Default::default(),
    };
    literal.validate()?;

    assert_eq!(builder.entity_id, literal.entity_id);
    assert_eq!(builder.metadata, literal.metadata);
    assert_eq!(builder.issuance_lifetime, literal.issuance_lifetime);
    assert_eq!(builder.validation, literal.validation);
    assert_eq!(builder.algorithms, literal.algorithms);
    assert_eq!(builder.xml, literal.xml);
    Ok(())
}

#[test]
fn idp_config_defaults_issuance_lifetime_to_five_minutes() -> Result<(), Box<dyn std::error::Error>>
{
    let config = IdpConfig::new(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IdpMetadataConfig::new(vec![SsoEndpoint::post("https://idp.example.com/sso")?]),
    );

    assert_eq!(config.issuance_lifetime, Duration::from_secs(300));
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn idp_builder_sets_issuance_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .issuance_lifetime(Duration::from_secs(600))
        .build()?;

    assert_eq!(config.issuance_lifetime, Duration::from_secs(600));
    Ok(())
}

#[test]
fn idp_config_rejects_zero_issuance_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
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
    let result = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .issuance_lifetime(Duration::MAX)
        .build();

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "IdP issuance lifetime must fit in time::Duration (at most i64::MAX seconds plus 999,999,999 nanoseconds)"
    ));
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn builders_start_on_recommended() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .build()?;
    let idp = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .build()?;

    assert_eq!(sp.validation, SpValidationPolicy::recommended());
    assert_eq!(idp.validation, IdpValidationPolicy::recommended());
    assert_eq!(
        sp.validation.assertions,
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        sp.validation.responses,
        ResponseSignaturePolicy::RequireForEncryptedCbc
    );
    assert_eq!(
        sp.validation.authn_requests,
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    );
    assert_eq!(
        sp.validation.audience,
        AudienceValidationPolicy::EvaluatePresentRestrictions
    );
    assert_eq!(
        sp.validation.name_id_creation,
        NameIdCreationPolicy::DoNotAllowCreate
    );
    assert_eq!(sp.validation.logout, LogoutPolicy::recommended());
    assert_eq!(
        sp.validation.xml_signatures,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility
    );
    assert_eq!(
        idp.validation.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent
    );
    Ok(())
}

#[test]
fn compatibility_policy_names_unsigned_choices_explicitly() {
    let sp = SpValidationPolicy::compatibility();
    let idp = IdpValidationPolicy::compatibility();

    assert_eq!(
        sp.assertions,
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        sp.responses,
        ResponseSignaturePolicy::AllowUnsignedEncryptedCbc
    );
    assert_eq!(
        sp.authn_requests,
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    );
    assert_eq!(sp.audience, AudienceValidationPolicy::SkipForCompatibility);
    assert_eq!(sp.logout, LogoutPolicy::compatibility());
    assert_eq!(
        idp.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        idp.logout.requests,
        LogoutSignaturePolicy::AllowUnsignedForCompatibility
    );
}

#[test]
fn raw_settings_keep_audience_and_logout_defaults_that_differ_from_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = EntitySetting::default();
    assert!(raw.validate_audience);
    assert!(raw.want_logout_request_signed);
    assert!(raw.want_logout_response_signed);

    let mut sp = SpConfig::new(
        EntityId::try_new("https://sp.example.com/metadata")?,
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    );
    sp.validation = SpValidationPolicy::compatibility();
    let converted = EntitySetting::try_from(&sp)?;
    assert!(!converted.validate_audience);
    assert!(!converted.want_logout_request_signed);
    assert!(!converted.want_logout_response_signed);

    let mut idp = IdpConfig::new(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IdpMetadataConfig::new(vec![SsoEndpoint::redirect("https://idp.example.com/sso")?]),
    );
    idp.validation = IdpValidationPolicy::compatibility();
    let converted = EntitySetting::try_from(&idp)?;
    assert!(converted.validate_audience);
    assert!(!converted.want_logout_request_signed);
    assert!(!converted.want_logout_response_signed);

    let raw_after = EntitySetting::default();
    assert!(raw_after.validate_audience);
    assert!(raw_after.want_logout_request_signed);
    assert!(raw_after.want_logout_response_signed);
    Ok(())
}

#[test]
fn recommended_preset_matches_classified_validation_and_hardenings_stay_independent() {
    let recommended_logout = LogoutPolicy {
        requests: LogoutSignaturePolicy::RequireSigned,
        responses: LogoutSignaturePolicy::RequireSigned,
    };
    assert_eq!(LogoutPolicy::recommended(), recommended_logout);
    assert_eq!(
        SpValidationPolicy::recommended(),
        SpValidationPolicy {
            assertions: AssertionSignaturePolicy::AllowUnsignedForCompatibility,
            responses: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
            authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
            audience: AudienceValidationPolicy::EvaluatePresentRestrictions,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
            logout: recommended_logout,
        }
    );
    assert_eq!(
        IdpValidationPolicy::recommended(),
        IdpValidationPolicy {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent,
            logout: recommended_logout,
        }
    );

    let assertion_signature = SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        ..SpValidationPolicy::recommended()
    };
    assert_eq!(
        assertion_signature.xml_signatures,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility
    );
    let rsa_sha2 = SpValidationPolicy {
        xml_signatures: XmlSignatureProfile::StrictRsaSha2,
        ..SpValidationPolicy::recommended()
    };
    assert_eq!(
        rsa_sha2.assertions,
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
}

#[test]
fn policy_defaults_start_on_recommended_and_field_defaults_stay_permissive() {
    assert!(!EntitySetting::default().want_message_signed);
    assert_eq!(
        SpValidationPolicy::default(),
        SpValidationPolicy::recommended()
    );
    assert_eq!(
        IdpValidationPolicy::default(),
        IdpValidationPolicy::recommended()
    );
    assert_eq!(LogoutPolicy::default(), LogoutPolicy::recommended());
    assert_eq!(
        AssertionSignaturePolicy::default(),
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        ResponseSignaturePolicy::default(),
        ResponseSignaturePolicy::AllowUnsignedEncryptedCbc
    );
    assert_eq!(
        AuthnRequestSigningPolicy::default(),
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    );
    assert_eq!(
        AuthnRequestValidationPolicy::default(),
        AuthnRequestValidationPolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        XmlSignatureProfile::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility
    );
    assert_eq!(
        SpValidationPolicy::recommended().xml_signatures,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility
    );
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn constructors_start_on_recommended() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpConfig::try_new(
        EntityId::try_new("https://sp.example.com/metadata")?,
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    )?;
    let idp = IdpConfig::try_new(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IdpMetadataConfig::new(vec![SsoEndpoint::redirect("https://idp.example.com/sso")?]),
    )?;
    let sp_new = SpConfig::new(
        EntityId::try_new("https://sp.example.com/metadata")?,
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    );
    let idp_new = IdpConfig::new(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IdpMetadataConfig::new(vec![SsoEndpoint::redirect("https://idp.example.com/sso")?]),
    );

    assert_eq!(sp.validation, SpValidationPolicy::recommended());
    assert_eq!(idp.validation, IdpValidationPolicy::recommended());
    assert_eq!(sp_new.validation, SpValidationPolicy::default());
    assert_eq!(idp_new.validation, IdpValidationPolicy::default());
    Ok(())
}

#[test]
fn legacy_algorithm_variants_are_risk_named() {
    let variants = [
        format!("{:?}", DigestAlgorithm::Sha1ForCompatibility),
        format!("{:?}", DataEncryptionAlgorithm::TripleDesForCompatibility),
        format!("{:?}", KeyEncryptionAlgorithm::Rsa15ForCompatibility),
    ];

    assert!(variants
        .iter()
        .all(|variant| variant.contains("Compatibility") || variant.contains("Legacy")));
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

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn sp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let elements_order = vec!["AssertionConsumerService".to_string()];
    let algorithms = AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha512,
        data_encryption: DataEncryptionAlgorithm::Aes128,
        key_encryption: KeyEncryptionAlgorithm::RsaOaepMgf1p,
        signed_reference_transforms: vec![TransformAlgorithm::ExclusiveCanonicalization],
        ..AlgorithmPolicy::default()
    };
    let xml = XmlPolicy {
        clock_drifts: (-1000, 2000),
        ..XmlPolicy::default()
    };
    let templates = TemplatePolicy {
        relay_state: "relay-state".to_string(),
        tag_prefix_protocol: "p".to_string(),
        ..TemplatePolicy::default()
    };

    let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(signing_credentials())
        .elements_order(elements_order.clone())
        .algorithms(algorithms.clone())
        .xml(xml)
        .templates(templates.clone())
        .build()?;

    assert_eq!(config.metadata.elements_order, Some(elements_order));
    assert_eq!(config.algorithms, algorithms);
    assert_eq!(config.xml, xml);
    assert_eq!(config.templates.relay_state, templates.relay_state);
    assert_eq!(
        config.templates.tag_prefix_protocol,
        templates.tag_prefix_protocol
    );
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn idp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let elements_order = vec!["SingleSignOnService".to_string()];
    let algorithms = AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha384,
        data_encryption: DataEncryptionAlgorithm::Aes256,
        key_encryption: KeyEncryptionAlgorithm::RsaOaepMgf1p,
        signed_reference_transforms: vec![TransformAlgorithm::EnvelopedSignature],
        ..AlgorithmPolicy::default()
    };
    let xml = XmlPolicy {
        clock_drifts: (-2000, 3000),
        ..XmlPolicy::default()
    };
    let templates = TemplatePolicy {
        relay_state: "idp-relay".to_string(),
        tag_prefix_assertion: "a".to_string(),
        ..TemplatePolicy::default()
    };

    let config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .elements_order(elements_order.clone())
        .algorithms(algorithms.clone())
        .xml(xml)
        .templates(templates.clone())
        .build()?;

    assert_eq!(config.metadata.elements_order, Some(elements_order));
    assert_eq!(config.algorithms, algorithms);
    assert_eq!(config.xml, xml);
    assert_eq!(config.templates.relay_state, templates.relay_state);
    assert_eq!(
        config.templates.tag_prefix_assertion,
        templates.tag_prefix_assertion
    );
    Ok(())
}

#[test]
fn entity_id_from_str_and_try_from_reject_empty_input() {
    let parsed = EntityId::from_str(" ");
    let tried = EntityId::try_from(String::new());

    assert!(matches!(parsed, Err(SamlError::Invalid(_))));
    assert!(matches!(tried, Err(SamlError::Invalid(_))));
}

#[test]
fn sp_builder_rejects_empty_entity_id() -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::new("   "))
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(signing_credentials())
        .build();

    assert!(matches!(result, Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn struct_literal_conversion_rejects_empty_entity_id() -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::new(
        EntityId::new(""),
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    );
    let result = EntitySetting::try_from(&config);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn sp_builder_rejects_signing_passphrase_without_signing_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        signing_key_passphrase: Some(Passphrase::new("test passphrase")),
        ..Credentials::default()
    };

    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .credentials(credentials)
        .build();

    assert_missing_key(result, "signing_key");
    Ok(())
}

#[test]
fn sp_builder_rejects_decryption_passphrase_without_decryption_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        decryption_key_passphrase: Some(Passphrase::new("test passphrase")),
        ..Credentials::default()
    };

    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .credentials(credentials)
        .build();

    assert_missing_key(result, "decryption_key");
    Ok(())
}

#[test]
fn sp_builder_rejects_missing_acs() -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .credentials(signing_credentials())
        .build();

    assert_missing_metadata(result, "AssertionConsumerService");
    Ok(())
}

#[test]
fn idp_builder_rejects_missing_sso() -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?).build();

    assert_missing_metadata(result, "SingleSignOnService");
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn sp_builder_requires_signing_credentials_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .build();

    assert_missing_key(result, "signing_key");
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn sp_builder_requires_signing_certificate_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        signing_key: Some(PrivateKeyPem::new("test signing key")),
        ..Credentials::default()
    };
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .credentials(credentials)
        .build();

    assert_missing_key(result, "signing_certificate");
    Ok(())
}

#[test]
fn sp_builder_allows_protocol_only_compatibility_without_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .build()?;

    assert_eq!(config.validation, SpValidationPolicy::compatibility());
    assert_eq!(config.credentials, Credentials::default());
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn sp_builder_requires_decryption_key_when_encrypted_assertions_are_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .xml(xml)
        .build();

    assert_missing_key(result, "decryption_key");
    Ok(())
}

#[test]
fn metadata_try_new_rejects_missing_required_endpoints() {
    let sp = SpMetadataConfig::try_new(Vec::new());
    let idp = IdpMetadataConfig::try_new(Vec::new());

    assert_missing_metadata(sp, "AssertionConsumerService");
    assert_missing_metadata(idp, "SingleSignOnService");
}

#[test]
fn xml_encryption_policy_defaults_to_plaintext_assertions() {
    assert_eq!(
        XmlPolicy::default().encryption.assertions,
        AssertionEncryptionPolicy::PlaintextAssertions
    );
}
