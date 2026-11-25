//! FIPS rejects the SHA-1 RSA-OAEP key transport these tests use.
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

use super::encrypted_assertion_elements::{
    alice, attributes, credentials, descriptors, each_encrypted_element, exchange_between, idp,
    signing_credentials, sp, sp_validation, sp_with_credentials, xml, CERT, IDP_ENTITY_ID,
    IDP_SSO_POST, SP_ENTITY_ID, UNKNOWN_CERT,
};

use saml_rs::constants::CertUse;
use saml_rs::metadata::SpMetadata;
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AttributeEncryptionPolicy, DigestAlgorithm,
    EntityId, IdentifierEncryptionPolicy, IdentityProvider, IdpConfig, KeyEncryptionAlgorithm,
    MaskGenerationFunction, MetadataTrustPolicy, RespondSso, SamlError, SpDescriptor, SsoAssertion,
    SsoEndpoint, XmlEncryptionPolicy,
};

const EC_CERT: &str = include_str!("../../tests/fixtures/key/prime256v1/cert.pem");
const UNREADABLE_CERT: &str = "AAAA";
const RSA_1024_CERT: &str = include_str!("../../tests/fixtures/key/rsa1024/cert.pem");
const RSA_KEY_VALUE: &str = "<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQAB</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>";

fn x509_data(certificates: &[&str]) -> String {
    let certificates: String = certificates
        .iter()
        .map(|certificate| {
            format!(
                "<ds:X509Certificate>{}</ds:X509Certificate>",
                normalize_cert_string(certificate)
            )
        })
        .collect();
    format!("<ds:X509Data>{certificates}</ds:X509Data>")
}

fn with_encryption_keys_first(metadata: &str, key_infos: &[String]) -> Result<String, String> {
    let first_encryption_key = metadata
        .find("use=\"encryption\"")
        .and_then(|attribute| metadata[..attribute].rfind('<'))
        .ok_or("metadata publishes no encryption key")?;
    let key_descriptors: String = key_infos
        .iter()
        .map(|key_info| {
            format!(
                "<KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{key_info}</ds:KeyInfo></KeyDescriptor>"
            )
        })
        .collect();
    let mut metadata = metadata.to_string();
    metadata.insert_str(first_encryption_key, &key_descriptors);
    Ok(metadata)
}

fn sp_descriptor(metadata: &str) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        metadata,
        MetadataTrustPolicy::Unverified,
    )
}

fn assert_encrypted(encryption: XmlEncryptionPolicy, xml: &str) {
    let mut hidden = Vec::new();
    if encryption.assertions == AssertionEncryptionPolicy::EncryptAssertions {
        hidden.extend([
            ("EncryptedAssertion", "alice-persistent-id"),
            ("EncryptedAssertion", "alice@example.com"),
        ]);
    }
    if encryption.identifiers == IdentifierEncryptionPolicy::EncryptIdentifiers {
        hidden.push(("EncryptedID", "alice-persistent-id"));
    }
    if encryption.attributes == AttributeEncryptionPolicy::EncryptAttributes {
        hidden.push(("EncryptedAttribute", "alice@example.com"));
    }
    assert!(!hidden.is_empty(), "{encryption:?} encrypts nothing");
    for (wrapper, plaintext) in hidden {
        assert!(xml.contains(wrapper), "{encryption:?}: no {wrapper}");
        assert!(
            !xml.contains(plaintext),
            "{encryption:?}: {plaintext} is visible"
        );
    }
}

fn assert_each_encrypted_key_names(xml: &str, certificate: &str) {
    let named = format!(
        "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        normalize_cert_string(certificate)
    );
    let encrypted_keys: Vec<&str> = xml
        .split("<xenc:EncryptedKey>")
        .skip(1)
        .filter_map(|rest| rest.split("</xenc:EncryptedKey>").next())
        .collect();
    assert!(!encrypted_keys.is_empty(), "no EncryptedKey: {xml}");
    for encrypted_key in encrypted_keys {
        assert!(encrypted_key.contains(&named), "{encrypted_key}");
    }
}

fn exchange_with_encryption_keys_first(
    idp: &IdentityProvider,
    encryption: XmlEncryptionPolicy,
    key_infos: &[String],
    own_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(XmlEncryptionPolicy::default())?;
    let (_, idp_descriptor) = descriptors(&sp, idp)?;
    let published = sp.metadata_xml().replace(
        &normalize_cert_string(CERT),
        &normalize_cert_string(own_key),
    );
    let metadata = with_encryption_keys_first(&published, key_infos)?;
    assert!(
        SpMetadata::from_xml(&metadata)?
            .as_metadata()
            .x509_certificates(CertUse::Encryption)
            .len()
            > 1
    );
    let exchange = exchange_between(&sp, &sp_descriptor(&metadata)?, idp, &idp_descriptor)?;
    assert_encrypted(encryption, &exchange.xml);
    assert_each_encrypted_key_names(&exchange.xml, CERT);
    let session = exchange.session?;
    assert_eq!(session.name_id(), &alice());
    assert_eq!(session.attributes(), &attributes());
    Ok(())
}

#[test]
fn identity_provider_encrypts_for_a_later_certificate_its_key_transport_can_use(
) -> Result<(), Box<dyn std::error::Error>> {
    let first_keys = [
        vec![x509_data(&[EC_CERT])],
        vec![x509_data(&[UNREADABLE_CERT])],
        vec![x509_data(&[EC_CERT, UNKNOWN_CERT])],
        vec![x509_data(&[EC_CERT]), x509_data(&[UNKNOWN_CERT, CERT])],
        vec![
            x509_data(&[EC_CERT]),
            x509_data(&[EC_CERT]) + &x509_data(&[UNKNOWN_CERT]),
        ],
        vec![
            x509_data(&[EC_CERT]),
            format!("{RSA_KEY_VALUE}{}", x509_data(&[UNKNOWN_CERT])),
        ],
        vec![
            x509_data(&[EC_CERT]),
            format!(
                "<ds:X509Data><ds:X509SubjectName>CN=sp</ds:X509SubjectName><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data>",
                normalize_cert_string(UNKNOWN_CERT)
            ),
        ],
    ];
    for encryption in each_encrypted_element() {
        for key_infos in &first_keys {
            exchange_with_encryption_keys_first(&idp(encryption)?, encryption, key_infos, CERT)?;
        }
    }
    Ok(())
}

#[test]
fn identity_provider_encrypts_for_a_later_key_with_a_key_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let named = format!(
        "<ds:KeyName>sp-encryption</ds:KeyName>{}",
        x509_data(&[CERT])
    );
    for encryption in each_encrypted_element() {
        exchange_with_encryption_keys_first(
            &idp(encryption)?,
            encryption,
            &[x509_data(&[EC_CERT]), named.clone()],
            EC_CERT,
        )?;
    }
    Ok(())
}

#[test]
fn identity_provider_skips_an_rsa_key_too_small_for_the_key_transport(
) -> Result<(), Box<dyn std::error::Error>> {
    for encryption in each_encrypted_element() {
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .credentials(credentials())
            .xml(xml(encryption))
            .algorithms(AlgorithmPolicy {
                key_encryption: KeyEncryptionAlgorithm::RsaOaep {
                    digest: DigestAlgorithm::Sha512,
                    mgf: MaskGenerationFunction::Mgf1Sha512,
                },
                ..AlgorithmPolicy::default()
            })
            .build()?,
        );
        exchange_with_encryption_keys_first(
            &idp,
            encryption,
            &[x509_data(&[RSA_1024_CERT])],
            CERT,
        )?;
    }
    Ok(())
}

fn crypto_error(
    encryption: XmlEncryptionPolicy,
    metadata: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match idp(encryption)?.initiate_sso(
        &sp_descriptor(metadata)?,
        SsoAssertion::new(alice()).attributes(attributes()),
        RespondSso::post(),
    ) {
        Err(error @ SamlError::Crypto { .. }) => {
            Ok(std::error::Error::source(&error).map(ToString::to_string))
        }
        other => Err(format!("expected a Crypto error, got {other:?}").into()),
    }
}

#[test]
fn identity_provider_reports_the_first_key_error_when_no_key_is_usable(
) -> Result<(), Box<dyn std::error::Error>> {
    let published = sp(XmlEncryptionPolicy::default())?
        .metadata_xml()
        .to_string();
    let sp_cert = normalize_cert_string(CERT);
    let ec_only = published.replace(&sp_cert, &normalize_cert_string(EC_CERT));
    let unreadable_only = published.replace(&sp_cert, UNREADABLE_CERT);
    let unreadable_then_ec =
        with_encryption_keys_first(&ec_only, &[x509_data(&[UNREADABLE_CERT])])?;
    for encryption in each_encrypted_element() {
        let first_error = crypto_error(encryption, &unreadable_only)?;
        assert_ne!(first_error, crypto_error(encryption, &ec_only)?);
        assert_eq!(crypto_error(encryption, &unreadable_then_ec)?, first_error);
    }
    Ok(())
}

#[test]
fn attribute_encryption_needs_no_certificate_when_the_assertion_has_no_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy {
        attributes: AttributeEncryptionPolicy::EncryptAttributes,
        ..XmlEncryptionPolicy::default()
    };
    let sp = sp_with_credentials(
        XmlEncryptionPolicy::default(),
        sp_validation(),
        signing_credentials(),
    )?;
    let idp = idp(encryption)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    assert!(SpMetadata::from_xml(sp.metadata_xml())?
        .as_metadata()
        .x509_certificates(CertUse::Encryption)
        .is_empty());

    idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(alice()),
        RespondSso::post(),
    )?;
    let with_attributes = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(alice()).attributes(attributes()),
        RespondSso::post(),
    );
    assert!(
        matches!(with_attributes, Err(SamlError::MissingMetadata(_))),
        "{with_attributes:?}"
    );
    Ok(())
}

#[test]
fn identity_provider_does_not_encrypt_for_a_key_of_another_service_provider_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let published = sp(XmlEncryptionPolicy::default())?.metadata_xml().replace(
        &normalize_cert_string(CERT),
        &normalize_cert_string(EC_CERT),
    );
    let other_role = format!(
        "<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{}</ds:KeyInfo></KeyDescriptor><AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/other-acs\" index=\"0\"/></SPSSODescriptor>",
        x509_data(&[CERT])
    );
    let role_end = published
        .find("</SPSSODescriptor>")
        .ok_or("metadata has no SP role")?
        + "</SPSSODescriptor>".len();
    let mut metadata = published.clone();
    metadata.insert_str(role_end, &other_role);
    for encryption in each_encrypted_element() {
        assert_eq!(
            crypto_error(encryption, &metadata)?,
            crypto_error(encryption, &published)?
        );
    }
    Ok(())
}
