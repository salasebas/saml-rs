//! `<EncryptedID>` and `<EncryptedAttribute>` through the typed
//! identity-provider and service-provider flows.
//!
//! SAML Core §2.2.4 and §2.7.3.2. An identity provider generates them only
//! when `XmlEncryptionPolicy` selects them, like `<EncryptedAssertion>`. A
//! service provider with a decryption key decrypts each one it receives
//! (Conformance §3.4). A service provider that selects one rejects the
//! plaintext form; that is library policy, not an OASIS receiver rule.
//!
//! FIPS rejects the SHA-1 RSA-OAEP key transport these tests use.
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

use super::post_validation::post_validation;
use saml_rs::tests::engine::IdpMessages;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::CertUse;
use saml_rs::metadata::{IdpMetadata, SpMetadata};
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    AcsEndpoint, AssertionEncryptionPolicy, AssertionSignaturePolicy, Attribute,
    AttributeEncryptionPolicy, AttributeNameFormat, AttributeValue, Attributes,
    AudienceValidationPolicy, CertificatePem, Credentials, EntityId, FormField,
    IdentifierEncryptionPolicy, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    Inbound, MetadataTrustPolicy, NameId, NameIdFormat, NameIdPolicy, Outbound, PrivateKeyPem,
    ReplayPolicy, RespondSso, ResponseSignaturePolicy, SamlError, SamlValidationContext,
    ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint,
    SsoResponse, SsoResponseBinding, SsoSession, StartSso, X509Credential, XmlEncryptionPolicy,
    XmlPolicy,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const NEXT_PRIVKEY: &str =
    include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const NEXT_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
const UNKNOWN_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.cer");

fn signing_credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

fn credentials() -> Credentials {
    signing_credentials().with_decryption_credential(X509Credential::new(
        CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

fn xml(encryption: XmlEncryptionPolicy) -> XmlPolicy {
    XmlPolicy {
        encryption,
        ..XmlPolicy::default()
    }
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn sp_validation() -> SpValidationPolicy {
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        audience: AudienceValidationPolicy::RequireRestriction,
        ..SpValidationPolicy::default()
    }
}

fn sp_with(
    encryption: XmlEncryptionPolicy,
    validation: SpValidationPolicy,
) -> Result<saml_rs::ServiceProvider, SamlError> {
    sp_with_credentials(encryption, validation, credentials())
}

fn sp_with_credentials(
    encryption: XmlEncryptionPolicy,
    validation: SpValidationPolicy,
    credentials: Credentials,
) -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(credentials)
        .validation(validation)
        .name_id_format(NameIdFormat::Persistent)
        .xml(xml(encryption))
        .build()?,
    ))
}

fn sp(encryption: XmlEncryptionPolicy) -> Result<saml_rs::ServiceProvider, SamlError> {
    sp_with(encryption, sp_validation())
}

fn idp(encryption: XmlEncryptionPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(credentials())
        .validation(IdpValidationPolicy::default())
        .xml(xml(encryption))
        .build()?,
    ))
}

fn descriptors(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?,
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?,
    ))
}

fn alice() -> NameId {
    NameId::new("alice-persistent-id").with_format(NameIdFormat::Persistent)
}

fn attributes() -> Attributes {
    Attributes::new(vec![
        Attribute::new("mail", vec![AttributeValue::new("alice@example.com")])
            .with_name_format(AttributeNameFormat::Basic)
            .with_friendly_name("Email address"),
        Attribute::new(
            "eduPersonAffiliation",
            vec![AttributeValue::new("member"), AttributeValue::new("staff")],
        )
        .with_name_format(AttributeNameFormat::Basic),
    ])
}

fn response_xml(outbound: &Outbound<SsoResponse>) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = outbound
        .post_form()?
        .fields()
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(STANDARD.decode(encoded)?)?)
}

struct Exchange {
    xml: String,
    session: Result<SsoSession, SamlError>,
}

/// SP-initiated SSO over HTTP-POST between an identity provider and a service
/// provider that each use their own encryption policy.
fn exchange(
    idp_encryption: XmlEncryptionPolicy,
    sp_encryption: XmlEncryptionPolicy,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = sp(sp_encryption)?;
    let idp = idp(idp_encryption)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    exchange_between(&sp, &sp_descriptor, &idp, &idp_descriptor)
}

/// SP-initiated SSO over HTTP-POST, in which `idp` reads `sp` from
/// `sp_descriptor`.
fn exchange_between(
    sp: &saml_rs::ServiceProvider,
    sp_descriptor: &SpDescriptor,
    idp: &saml_rs::IdentityProvider,
    idp_descriptor: &IdpDescriptor,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let started = sp.start_sso(idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        sp_descriptor,
        &received,
        SsoAssertion::new(alice()).with_attributes(attributes()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    let session = sp.finish_sso(
        idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    );
    Ok(Exchange { xml, session })
}

fn ids_and_attributes() -> XmlEncryptionPolicy {
    XmlEncryptionPolicy {
        identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
        attributes: AttributeEncryptionPolicy::EncryptAttributes,
        ..XmlEncryptionPolicy::default()
    }
}

#[test]
fn encrypted_id_carries_the_name_id_to_the_service_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy {
        identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
        ..XmlEncryptionPolicy::default()
    };
    let exchange = exchange(encryption, encryption)?;

    assert!(
        exchange.xml.contains("<saml:EncryptedID>"),
        "{}",
        exchange.xml
    );
    assert!(!exchange.xml.contains("<saml:NameID"), "{}", exchange.xml);
    assert!(!exchange.xml.contains("alice-persistent-id"));
    assert!(!exchange.xml.contains(PERSISTENT));
    assert!(exchange.xml.contains("<saml:Attribute Name=\"mail\""));

    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn requested_encrypted_name_id_is_encrypted_in_the_assertion_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(credentials())
        .validation(sp_validation())
        .name_id_format(NameIdFormat::Custom(
            "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted".into(),
        ))
        .build()?,
    );
    let idp_with_assertion_encryption = idp(XmlEncryptionPolicy {
        assertions: AssertionEncryptionPolicy::EncryptAssertions,
        identifiers: IdentifierEncryptionPolicy::PlaintextIdentifiers,
        ..XmlEncryptionPolicy::default()
    })?;
    let idp = idp(XmlEncryptionPolicy {
        identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
        ..XmlEncryptionPolicy::default()
    })?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let encoded = started
        .outbound
        .post_form()?
        .value("SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let request_xml = String::from_utf8(STANDARD.decode(encoded)?)?;
    let affiliation = "https://affiliation.example.com";
    let request_xml = request_xml.replace(
        "<samlp:NameIDPolicy ",
        &format!("<samlp:NameIDPolicy SPNameQualifier=\"{affiliation}\" "),
    );
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(request_xml.as_bytes()),
        )]),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .name_id_policy()
            .and_then(NameIdPolicy::sp_name_qualifier),
        Some(affiliation)
    );
    let refused = idp_with_assertion_encryption.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(alice()),
        RespondSso::post(),
    );
    assert!(matches!(
        refused,
        Err(SamlError::NameIdPolicyRequiresEncryptedId)
    ));

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(alice()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.contains("<saml:Subject><saml:EncryptedID>"));
    assert!(!xml.contains("<saml:NameID"));

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id(), &alice());
    Ok(())
}

#[test]
fn encrypted_attribute_carries_each_attribute_to_the_service_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy {
        attributes: AttributeEncryptionPolicy::EncryptAttributes,
        ..XmlEncryptionPolicy::default()
    };
    let exchange = exchange(encryption, encryption)?;

    assert_eq!(exchange.xml.matches("<saml:EncryptedAttribute>").count(), 2);
    assert!(
        !exchange.xml.contains("<saml:Attribute "),
        "{}",
        exchange.xml
    );
    assert!(!exchange.xml.contains("alice@example.com"));
    assert!(exchange.xml.contains("<saml:NameID"));

    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

fn next_decryption_key() -> X509Credential {
    X509Credential::new(
        CertificatePem::new(NEXT_CERT),
        PrivateKeyPem::new(NEXT_PRIVKEY),
    )
}

/// Service provider metadata whose encryption certificate is
/// `encryption_cert`, which may name a key that no service provider holds.
fn metadata_publishing(encryption_cert: &str) -> Result<String, SamlError> {
    let published = sp_with_credentials(
        XmlEncryptionPolicy::default(),
        sp_validation(),
        signing_credentials().with_decryption_credential(next_decryption_key()),
    )?;
    Ok(published.metadata_xml().replace(
        &normalize_cert_string(NEXT_CERT),
        &normalize_cert_string(encryption_cert),
    ))
}

/// SSO in which the identity provider encrypts for `encryption_cert` and the
/// service provider decrypts with `sp_credentials`.
fn exchange_encrypted_for(
    encryption: XmlEncryptionPolicy,
    encryption_cert: &str,
    sp_credentials: Credentials,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = sp_with_credentials(
        XmlEncryptionPolicy::default(),
        sp_validation(),
        sp_credentials,
    )?;
    let idp = idp(encryption)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &metadata_publishing(encryption_cert)?,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    exchange_between(&sp, &sp_descriptor, &idp, &idp_descriptor)
}

fn each_encrypted_element() -> [XmlEncryptionPolicy; 3] {
    [
        XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
        XmlEncryptionPolicy {
            identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
            ..XmlEncryptionPolicy::default()
        },
        XmlEncryptionPolicy {
            attributes: AttributeEncryptionPolicy::EncryptAttributes,
            ..XmlEncryptionPolicy::default()
        },
    ]
}

#[test]
fn raw_key_transport_override_drops_typed_oaep_parameters() -> Result<(), Box<dyn std::error::Error>>
{
    use saml_rs::constants::{key_encryption_algorithm::RSA_OAEP_MGF1P, Binding};
    use saml_rs::crypto::{
        decrypt_assertion_with_limits, keys::read_private_key, AssertionDecryptionOptions,
    };
    use saml_rs::{
        AlgorithmPolicy, DigestAlgorithm, KeyEncryptionAlgorithm, MaskGenerationFunction,
    };

    let sp = sp(XmlEncryptionPolicy {
        assertions: AssertionEncryptionPolicy::EncryptAssertions,
        ..XmlEncryptionPolicy::default()
    })?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(credentials())
        .xml(xml(XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        }))
        .algorithms(AlgorithmPolicy {
            key_encryption: KeyEncryptionAlgorithm::RsaOaep {
                digest: DigestAlgorithm::Sha256,
                mgf: MaskGenerationFunction::Mgf1Sha256,
            },
            ..AlgorithmPolicy::default()
        })
        .build()?,
    );
    let mut raw = idp.engine().clone();
    raw.setting.key_encryption_algorithm = RSA_OAEP_MGF1P.into();
    let response = raw.create_login_response(
        sp.engine(),
        Binding::Post,
        &saml_rs::entity::User::new("alice-persistent-id"),
        &saml_rs::idp::LoginResponseOptions::default(),
    )?;
    let xml = String::from_utf8(STANDARD.decode(&response.context)?)?;
    let document = bergshamra::xml::uppsala::parse(&xml)?;
    assert!(!document
        .descendants(document.root())
        .into_iter()
        .any(|node| {
            document.element(node).is_some_and(|element| {
                element.matches_name_ns("http://www.w3.org/2009/xmlenc11#", "MGF")
            })
        }));
    let key = read_private_key(PRIVKEY, None)?;
    let (_, assertion) = decrypt_assertion_with_limits(
        &xml,
        &key,
        AssertionDecryptionOptions::default(),
        saml_rs::XmlLimits::default(),
    )?;
    assert!(assertion.contains("alice-persistent-id"));
    Ok(())
}

#[test]
fn metadata_publishes_each_encryption_certificate_in_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let rolling = credentials().with_decryption_credential(next_decryption_key());
    let sp = sp_with_credentials(
        XmlEncryptionPolicy::default(),
        sp_validation(),
        rolling.clone(),
    )?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(rolling)
        .validation(IdpValidationPolicy::default())
        .build()?,
    );
    let published = vec![
        normalize_cert_string(CERT),
        normalize_cert_string(NEXT_CERT),
    ];

    assert_eq!(
        SpMetadata::from_xml(sp.metadata_xml())?
            .as_metadata()
            .x509_certificates(CertUse::Encryption),
        published
    );
    assert_eq!(
        IdpMetadata::from_xml(idp.metadata_xml())?
            .as_metadata()
            .x509_certificates(CertUse::Encryption),
        published
    );
    for metadata in [sp.metadata_xml(), idp.metadata_xml()] {
        assert_eq!(
            metadata.matches("use=\"encryption\"").count(),
            2,
            "{metadata}"
        );
    }
    Ok(())
}

#[test]
fn service_provider_decrypts_elements_made_for_either_published_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let rolling = credentials().with_decryption_credential(next_decryption_key());
    for encryption in each_encrypted_element() {
        for encryption_cert in [CERT, NEXT_CERT] {
            let exchange = exchange_encrypted_for(encryption, encryption_cert, rolling.clone())?;

            assert!(
                !exchange.xml.contains("alice-persistent-id")
                    || !exchange.xml.contains("alice@example.com")
            );
            let session = exchange.session?;
            assert_eq!(session.name_id(), &alice());
            assert_eq!(session.attributes(), &attributes());
        }
    }
    Ok(())
}

#[test]
fn service_provider_without_the_key_keeps_the_single_key_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let rolling = credentials().with_decryption_credential(next_decryption_key());
    for encryption in each_encrypted_element() {
        let single_key = exchange_encrypted_for(encryption, UNKNOWN_CERT, credentials())?.session;
        let both_keys = exchange_encrypted_for(encryption, UNKNOWN_CERT, rolling.clone())?.session;

        let (Err(single_key), Err(both_keys)) = (single_key, both_keys) else {
            return Err("a key that is not configured decrypted".into());
        };
        assert!(
            matches!(both_keys, SamlError::Crypto { .. }),
            "{both_keys:?}"
        );
        assert_eq!(
            std::error::Error::source(&both_keys).map(ToString::to_string),
            std::error::Error::source(&single_key).map(ToString::to_string)
        );
    }
    Ok(())
}

#[test]
fn identifiers_and_attributes_stay_plaintext_until_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy::default(),
        XmlEncryptionPolicy::default(),
    )?;

    assert!(!exchange.xml.contains("EncryptedID"));
    assert!(!exchange.xml.contains("EncryptedAttribute"));
    assert!(!exchange.xml.contains("EncryptedAssertion"));
    assert!(exchange.xml.contains("<saml:NameID"));
    assert!(exchange.xml.contains("<saml:Attribute Name=\"mail\""));
    exchange.session?;
    Ok(())
}

#[test]
fn identifier_and_attribute_encryption_do_not_select_assertion_encryption(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = ids_and_attributes();
    assert_eq!(
        encryption.assertions,
        XmlEncryptionPolicy::default().assertions
    );
    let exchange = exchange(encryption, encryption)?;

    assert!(!exchange.xml.contains("EncryptedAssertion"));
    assert!(exchange.xml.contains("<saml:Assertion "));
    assert!(exchange.xml.contains("<saml:EncryptedID>"));
    assert_eq!(exchange.xml.matches("<saml:EncryptedAttribute>").count(), 2);
    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn encrypted_elements_round_trip_inside_an_encrypted_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy {
        assertions: AssertionEncryptionPolicy::EncryptAssertions,
        ..ids_and_attributes()
    };
    let exchange = exchange(encryption, encryption)?;

    assert!(exchange.xml.contains("EncryptedAssertion"));
    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn service_provider_decrypts_encrypted_elements_it_does_not_select(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(ids_and_attributes(), XmlEncryptionPolicy::default())?;

    assert!(exchange.xml.contains("<saml:EncryptedID>"));
    assert_eq!(exchange.xml.matches("<saml:EncryptedAttribute>").count(), 2);
    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn service_provider_decrypts_an_encrypted_assertion_it_does_not_select(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
        XmlEncryptionPolicy::default(),
    )?;

    assert!(exchange.xml.contains("EncryptedAssertion"));
    assert!(!exchange.xml.contains("alice-persistent-id"));
    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn encrypted_assertion_is_decrypted_over_simple_sign() -> Result<(), Box<dyn std::error::Error>> {
    for sp_encryption in [
        XmlEncryptionPolicy::default(),
        XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
    ] {
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::simple_sign(SP_ACS)?.with_default(),
            )
            .credentials(credentials())
            .name_id_format(NameIdFormat::Persistent)
            .validation(SpValidationPolicy::default())
            .xml(xml(sp_encryption))
            .build()?,
        );
        let idp = idp(XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        })?;
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = sp.start_sso(
            &idp_descriptor,
            StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
        )?;
        let received = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(alice()).with_attributes(attributes()),
            RespondSso::simple_sign(),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::simple_sign(response.post_form()?.fields().to_vec()),
            validation(),
        )?;
        assert_eq!(session.name_id(), &alice(), "{sp_encryption:?}");
        assert_eq!(session.attributes(), &attributes(), "{sp_encryption:?}");
    }
    Ok(())
}

#[test]
fn service_provider_that_selects_encrypted_assertions_rejects_a_plaintext_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy::default(),
        XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
    )?;
    match exchange.session {
        Err(SamlError::EncryptionRequired {
            element: "Assertion",
        }) => Ok(()),
        other => Err(format!("expected EncryptionRequired for Assertion, got {other:?}").into()),
    }
}

#[test]
fn service_provider_that_selects_encrypted_id_rejects_a_plaintext_name_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy::default(),
        XmlEncryptionPolicy {
            identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
            ..XmlEncryptionPolicy::default()
        },
    )?;
    match exchange.session {
        Err(SamlError::EncryptionRequired { element: "NameID" }) => Ok(()),
        other => Err(format!("expected EncryptionRequired for NameID, got {other:?}").into()),
    }
}

#[test]
fn service_provider_that_selects_encrypted_attribute_rejects_a_plaintext_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy {
            identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
            ..XmlEncryptionPolicy::default()
        },
        ids_and_attributes(),
    )?;
    match exchange.session {
        Err(SamlError::EncryptionRequired {
            element: "Attribute",
        }) => Ok(()),
        other => Err(format!("expected EncryptionRequired for Attribute, got {other:?}").into()),
    }
}

#[test]
fn service_provider_builder_requires_a_decryption_key_for_encrypted_elements(
) -> Result<(), Box<dyn std::error::Error>> {
    for encryption in [
        XmlEncryptionPolicy {
            identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
            ..XmlEncryptionPolicy::default()
        },
        XmlEncryptionPolicy {
            attributes: AttributeEncryptionPolicy::EncryptAttributes,
            ..XmlEncryptionPolicy::default()
        },
    ] {
        let built = SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .xml(xml(encryption))
        .build();
        match built {
            Err(SamlError::MissingKey(key)) if key == "decryption_credential" => {}
            other => return Err(format!("expected MissingKey, got {other:?}").into()),
        }
    }
    Ok(())
}

/// An unsigned `<Assertion>` whose `<EncryptedID>` no signature covers.
const UNSIGNED_SIBLING: &str = concat!(
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
    "ID=\"_unsigned_sibling\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">",
    "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:EncryptedID>",
    "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
    "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>",
    "</xenc:EncryptedData></saml:EncryptedID></saml:Subject></saml:Assertion>",
);

#[test]
fn encrypted_id_outside_the_signed_assertion_is_not_decrypted(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy {
        assertions: AssertionEncryptionPolicy::EncryptAssertions,
        identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
        ..XmlEncryptionPolicy::default()
    };
    let sp = sp_with(
        encryption,
        SpValidationPolicy {
            responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
            ..sp_validation()
        },
    )?;
    let idp = idp(encryption)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(alice()),
        RespondSso::post().allow_unsigned_encrypted_cbc(),
    )?;
    let xml = response_xml(&response)?;
    assert!(!xml.contains("<ds:Signature"), "{xml}");
    let end_tag = "</saml:EncryptedAssertion>";
    let end = xml.find(end_tag).ok_or("missing EncryptedAssertion")? + end_tag.len();
    let tampered = format!("{}{UNSIGNED_SIBLING}{}", &xml[..end], &xml[end..]);
    let fields = response
        .post_form()?
        .fields()
        .iter()
        .map(|field| match field.name() {
            "SAMLResponse" => FormField::new("SAMLResponse", STANDARD.encode(tampered.as_bytes())),
            _ => field.clone(),
        })
        .collect::<Vec<_>>();

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(fields),
        validation(),
    ) {
        Err(SamlError::PotentialWrappingAttack) => Ok(()),
        other => Err(format!(
            "expected the unsigned sibling to be rejected before decryption, got {other:?}"
        )
        .into()),
    }
}

const ASSERTION_NS_DECLARATION: &str = " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";
const XENC_NS_DECLARATION: &str = " xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"";

/// Remove the `occurrence`th (0-based) copy of `declaration` from `xml`.
fn without_declaration(
    xml: &str,
    declaration: &str,
    occurrence: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let (start, _) = xml
        .match_indices(declaration)
        .nth(occurrence)
        .ok_or("missing namespace declaration")?;
    Ok(format!(
        "{}{}",
        &xml[..start],
        &xml[start + declaration.len()..]
    ))
}

/// Exclusive canonicalization renders a namespace where it is used, so moving
/// a declaration to an ancestor keeps every signature valid.
#[test]
fn encrypted_elements_decrypt_with_namespaces_declared_on_the_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = ids_and_attributes();
    let sp = sp(encryption)?;
    let idp = idp(encryption)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(alice()).with_attributes(attributes()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;

    // The assertion prefix is declared on the Response alone.
    let saml_on_response = without_declaration(&xml, ASSERTION_NS_DECLARATION, 1)?;
    // The XML-Enc prefix is declared on the Response alone.
    let mut xenc_on_response = xml.clone();
    while xenc_on_response.contains(XENC_NS_DECLARATION) {
        xenc_on_response = without_declaration(&xenc_on_response, XENC_NS_DECLARATION, 0)?;
    }
    let response_tag_end = xenc_on_response.find('>').ok_or("missing Response tag")?;
    xenc_on_response.insert_str(response_tag_end, XENC_NS_DECLARATION);

    for tampered in [saml_on_response, xenc_on_response] {
        let fields = response
            .post_form()?
            .fields()
            .iter()
            .map(|field| match field.name() {
                "SAMLResponse" => {
                    FormField::new("SAMLResponse", STANDARD.encode(tampered.as_bytes()))
                }
                _ => field.clone(),
            })
            .collect::<Vec<_>>();
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::post(fields),
            post_validation(&mut Default::default()),
        )?;
        assert_eq!(session.name_id(), &alice());
        assert_eq!(session.attributes(), &attributes());
    }
    Ok(())
}
