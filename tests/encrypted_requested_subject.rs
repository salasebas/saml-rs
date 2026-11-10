//! `<EncryptedID>` in the requested `<Subject>` of an `<AuthnRequest>`.
//!
//! Conformance §3.4: the identity provider processes the encrypted form where
//! it processes the requested `<NameID>` (Core §3.4.1). CBC ciphertext is
//! decrypted only under a verified signature; AES-GCM authenticates itself.
//! That restriction is library policy.
//!
//! FIPS rejects the SHA-1 RSA-OAEP key transport these tests use.
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

use std::time::SystemTime;

use bergshamra::{encrypt, EncContext, KeysManager};
use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::crypto::{
    construct_saml_signature,
    keys::{load_certificate, load_private_key},
};
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, DecryptionCredential,
    EntityId, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy,
    NameId, NameIdFormat, PrivateKeyPem, ReplayPolicy, RequestedSubject,
    RequestedSubjectIdentifier, Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, StartSso,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const NEXT_PRIVKEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const NEXT_CERT: &str = include_str!("fixtures/key/idp/cert.cer");
const UNKNOWN_CERT: &str = include_str!("fixtures/key/sp/cert.cer");

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(Credentials {
                signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
                signing_certificate: Some(CertificatePem::new(CERT)),
                ..Credentials::default()
            })
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )
}

fn idp() -> Result<Saml<saml_rs::Idp>, SamlError> {
    idp_with_credentials(idp_credentials())
}

fn idp_credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        encryption_certificate: Some(CertificatePem::new(CERT)),
        decryption_key: Some(PrivateKeyPem::new(PRIVKEY)),
        ..Credentials::default()
    }
}

fn idp_with_credentials(credentials: Credentials) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials)
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )
}

#[derive(Debug, Clone, Copy)]
enum Signing {
    Signed,
    Unsigned,
}

/// An `<EncryptedID>` that carries `<NameID>` for the identity provider's
/// encryption certificate.
fn encrypted_id(data_alg: &str) -> Result<String, Box<dyn std::error::Error>> {
    encrypted_id_for(CERT, data_alg)
}

/// An `<EncryptedID>` that carries `<NameID>` for `encryption_cert`.
fn encrypted_id_for(
    encryption_cert: &str,
    data_alg: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let name_id = format!(
        "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"{EMAIL_FORMAT}\">alice@example.com</saml:NameID>"
    );
    let template = format!(
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"{data_alg}\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{RSA_OAEP}\"/><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"
    );
    let mut manager = KeysManager::new();
    manager.add_key(load_certificate(encryption_cert)?);
    let encrypted_data = encrypt(&EncContext::new(manager), &template, name_id.as_bytes())?;
    Ok(format!(
        "<saml:EncryptedID>{encrypted_data}</saml:EncryptedID>"
    ))
}

/// The requested identifier the identity provider reads from an
/// SP-initiated HTTP-POST `<AuthnRequest>` that carries `subject`.
fn received_identifier(
    subject: &str,
    signing: Signing,
) -> Result<RequestedSubjectIdentifier, Box<dyn std::error::Error>> {
    received_by(&idp()?, subject, signing)
}

fn received_by(
    idp: &Saml<saml_rs::Idp>,
    subject: &str,
    signing: Signing,
) -> Result<RequestedSubjectIdentifier, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let context = started.outbound.raw_context();
    if context.binding != Binding::Post {
        return Err("expected an HTTP-POST AuthnRequest".into());
    }
    let xml = String::from_utf8(base64_decode(&context.context)?)?;
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    let xml = format!(
        "{}<saml:Subject>{subject}</saml:Subject>{}",
        &xml[..position],
        &xml[position..]
    );
    let xml = match signing {
        Signing::Signed => construct_saml_signature(
            &xml,
            true,
            &load_private_key(PRIVKEY, None)?,
            CERT,
            RSA_SHA256,
            &[],
            None,
        )?,
        Signing::Unsigned => xml,
    };
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(xml.as_bytes()),
        )]),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility),
    )?;
    Ok(received
        .message()
        .requested_subject()
        .map(RequestedSubject::identifier)
        .cloned()
        .ok_or("missing requested Subject")?)
}

fn alice() -> RequestedSubjectIdentifier {
    RequestedSubjectIdentifier::NameId(NameId::new(
        "alice@example.com",
        Some(NameIdFormat::EmailAddress),
    ))
}

#[test]
fn signed_request_encrypted_id_is_the_requested_name_id() -> Result<(), Box<dyn std::error::Error>>
{
    for data_alg in [AES256_CBC, AES128_GCM] {
        assert_eq!(
            received_identifier(&encrypted_id(data_alg)?, Signing::Signed)?,
            alice(),
            "{data_alg}"
        );
    }
    Ok(())
}

#[test]
fn unsigned_request_encrypted_id_is_decrypted_only_with_gcm(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        received_identifier(&encrypted_id(AES128_GCM)?, Signing::Unsigned)?,
        alice()
    );
    assert_eq!(
        received_identifier(&encrypted_id(AES256_CBC)?, Signing::Unsigned)?,
        RequestedSubjectIdentifier::EncryptedId
    );
    Ok(())
}

#[test]
fn encrypted_id_made_for_either_published_certificate_is_the_requested_name_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with_credentials(Credentials {
        additional_decryption_keys: vec![DecryptionCredential {
            certificate: CertificatePem::new(NEXT_CERT),
            key: PrivateKeyPem::new(NEXT_PRIVKEY),
            passphrase: None,
        }],
        ..idp_credentials()
    })?;
    for encryption_cert in [CERT, NEXT_CERT] {
        let encrypted = encrypted_id_for(encryption_cert, AES128_GCM)?;
        assert_eq!(received_by(&idp, &encrypted, Signing::Signed)?, alice());
    }
    let encrypted = encrypted_id_for(UNKNOWN_CERT, AES128_GCM)?;
    assert_eq!(
        received_by(&idp, &encrypted, Signing::Signed)?,
        RequestedSubjectIdentifier::EncryptedId
    );
    Ok(())
}

#[test]
fn encrypted_id_that_does_not_decrypt_stays_unread() -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypted_id(AES128_GCM)?;
    let start = encrypted
        .rfind("<xenc:CipherValue>")
        .ok_or("missing CipherValue")?
        + "<xenc:CipherValue>".len();
    let tampered = format!("{}AAAA{}", &encrypted[..start], &encrypted[start + 4..]);
    assert_eq!(
        received_identifier(&tampered, Signing::Signed)?,
        RequestedSubjectIdentifier::EncryptedId
    );
    Ok(())
}
