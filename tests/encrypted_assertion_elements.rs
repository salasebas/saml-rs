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

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeEncryptionPolicy,
    AttributeNameFormat, AttributeValue, Attributes, AudienceValidationPolicy, AuthnRequest,
    BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, MetadataTrustPolicy, NameId, NameIdFormat, Outbound, PrivateKeyPem,
    ReplayPolicy, RespondSso, ResponseSignaturePolicy, Saml, SamlError, SamlValidationContext,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, SsoResponseBinding,
    SsoSession, StartSso, Subject, XmlEncryptionPolicy, XmlPolicy,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        encryption_certificate: Some(CertificatePem::new(CERT)),
        decryption_key: Some(PrivateKeyPem::new(PRIVKEY)),
        ..Credentials::default()
    }
}

fn xml(encryption: XmlEncryptionPolicy) -> XmlPolicy {
    XmlPolicy {
        encryption: encryption.with_insecure_software_rsa_key_transport_decryption_allowed(),
        ..XmlPolicy::default()
    }
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sp_validation() -> SpValidationPolicy {
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        audience: AudienceValidationPolicy::Validate,
        ..SpValidationPolicy::recommended()
    }
}

fn sp_with(
    encryption: XmlEncryptionPolicy,
    validation: SpValidationPolicy,
) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(validation)
            .xml(xml(encryption))
            .build()?,
    )
}

fn sp(encryption: XmlEncryptionPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    sp_with(encryption, sp_validation())
}

fn idp(encryption: XmlEncryptionPolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .xml(xml(encryption))
            .build()?,
    )
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
        IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
    ))
}

fn alice() -> NameId {
    NameId::new("alice-persistent-id", Some(NameIdFormat::Persistent))
}

fn attributes() -> Attributes {
    Attributes::new(vec![
        Attribute::with_name_format(
            "mail",
            AttributeNameFormat::Basic,
            vec![AttributeValue::new("alice@example.com")],
        ),
        Attribute::with_name_format(
            "eduPersonAffiliation",
            AttributeNameFormat::Basic,
            vec![AttributeValue::new("member"), AttributeValue::new("staff")],
        ),
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
    Ok(String::from_utf8(base64_decode(encoded)?)?)
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
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(alice(), Vec::new()),
        RespondSso::post().attributes(attributes()),
    )?;
    let xml = response_xml(&response)?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    );
    Ok(Exchange { xml, session })
}

fn ids_and_attributes() -> XmlEncryptionPolicy {
    let mut encryption = XmlEncryptionPolicy::encrypt_ids();
    encryption.attributes = AttributeEncryptionPolicy::EncryptAttributes;
    encryption
}

#[test]
fn encrypted_id_carries_the_name_id_to_the_service_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy::encrypt_ids();
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
fn encrypted_attribute_carries_each_attribute_to_the_service_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlEncryptionPolicy::encrypt_attributes();
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
    let mut encryption = ids_and_attributes();
    encryption.assertions = XmlEncryptionPolicy::encrypt_assertions().assertions;
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
        XmlEncryptionPolicy::encrypt_assertions(),
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
        XmlEncryptionPolicy::encrypt_assertions(),
    ] {
        let sp = Saml::sp(
            SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
                .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS)?.mark_default())
                .credentials(credentials())
                .validation(SpValidationPolicy::recommended())
                .xml(xml(sp_encryption))
                .build()?,
        )?;
        let idp = idp(XmlEncryptionPolicy::encrypt_assertions())?;
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = sp.start_sso(
            &idp_descriptor,
            StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
        )?;
        let received = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            Subject::new(alice(), Vec::new()),
            RespondSso::simple_sign().attributes(attributes()),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::simple_sign(response.post_form()?.fields().to_vec()),
            validation(),
        )?;
        assert_eq!(session.name_id(), &alice(), "{sp_encryption:?}");
        assert_eq!(session.attributes(), &attributes(), "{sp_encryption:?}");
    }
    Ok(())
}

#[test]
fn service_provider_that_selects_encrypted_id_rejects_a_plaintext_name_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(
        XmlEncryptionPolicy::default(),
        XmlEncryptionPolicy::encrypt_ids(),
    )?;
    match exchange.session {
        Err(SamlError::EncryptionRequired { element: "NameID" }) => Ok(()),
        other => Err(format!("expected EncryptionRequired for NameID, got {other:?}").into()),
    }
}

#[test]
fn service_provider_that_selects_encrypted_attribute_rejects_a_plaintext_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(XmlEncryptionPolicy::encrypt_ids(), ids_and_attributes())?;
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
        XmlEncryptionPolicy::encrypt_ids(),
        XmlEncryptionPolicy::encrypt_attributes(),
    ] {
        let built = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .xml(xml(encryption))
            .build();
        match built {
            Err(SamlError::MissingKey(key)) if key == "decryption_key" => {}
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
    let mut encryption = XmlEncryptionPolicy::encrypt_ids();
    encryption.assertions = XmlEncryptionPolicy::encrypt_assertions().assertions;
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
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(alice(), Vec::new()),
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
            "SAMLResponse" => FormField::new("SAMLResponse", base64_encode(tampered.as_bytes())),
            _ => field.clone(),
        })
        .collect::<Vec<_>>();

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(fields),
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
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(alice(), Vec::new()),
        RespondSso::post().attributes(attributes()),
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
                    FormField::new("SAMLResponse", base64_encode(tampered.as_bytes()))
                }
                _ => field.clone(),
            })
            .collect::<Vec<_>>();
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(fields),
            validation(),
        )?;
        assert_eq!(session.name_id(), &alice());
        assert_eq!(session.attributes(), &attributes());
    }
    Ok(())
}
