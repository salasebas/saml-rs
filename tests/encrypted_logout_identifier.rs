//! `<EncryptedID>` in a Single Logout `LogoutRequest`, through the typed
//! identity-provider and service-provider flows.
//!
//! Conformance Requirements §3.4: an operational mode processes and generates
//! `<EncryptedID>` wherever it processes or generates `<NameID>`, and Core
//! §3.7.1 allows it in `LogoutRequest`. Generation stays off until
//! `StartSlo::identifier_encryption` selects it.
//!
//! FIPS rejects the SHA-1 RSA-OAEP key transport these tests use.
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

#[path = "common/unsigned_post.rs"]
mod unsigned_post;

#[path = "common/post_validation.rs"]
mod post_validation;
use post_validation::post_validation;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bergshamra::keys::loader::load_x509_cert_pem;
use bergshamra::{encrypt, EncContext, KeysManager};
use flate2::read::DeflateDecoder;
use saml_rs::constants::status_code;
use saml_rs::{
    AcsEndpoint, CertificatePem, Credentials, EntityId, FormField, IdentifierEncryptionPolicy,
    IdentityProvider, IdpConfig, IdpDescriptor, InMemoryReplayCache, Inbound, LogoutBinding,
    LogoutRequest, LogoutResponse, LogoutSubject, MetadataTrustPolicy, NameId, NameIdFormat,
    Outbound, OutboundDelivery, OutstandingLogout, PrivateKeyPem, Received, ReplayPolicy,
    RespondSlo, RespondSso, SamlError, SamlValidationContext, ServiceProvider, SessionIndex,
    SloEndpoint, SoapBodyElement, SoapChannel, SoapRequest, SpConfig, SpDescriptor, SsoAssertion,
    SsoEndpoint, StartSlo, StartSso, Status, SubordinateStatusCode, X509Credential,
    XmlEncryptionPolicy, XmlPolicy,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";
const PRINCIPAL: &str = "alice-persistent-id";
const BASE_ID: &str = r#"<saml:BaseID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:example="urn:example:identifiers"
    xsi:type="example:AccountID">opaque</saml:BaseID>"#;

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const NEXT_PRIVKEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const NEXT_CERT: &str = include_str!("fixtures/key/idp/cert.cer");

const BINDINGS: [LogoutBinding; 4] = [
    LogoutBinding::Post,
    LogoutBinding::Redirect,
    LogoutBinding::SimpleSign,
    LogoutBinding::Soap,
];

#[derive(Debug, Clone, Copy)]
enum Initiator {
    Sp,
    Idp,
}

const INITIATORS: [Initiator; 2] = [Initiator::Sp, Initiator::Idp];

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
    let mut xml = XmlPolicy::default();
    xml.encryption = encryption;
    xml
}

fn slo_endpoints(host: &str) -> Result<Vec<SloEndpoint>, SamlError> {
    Ok(vec![
        SloEndpoint::post(format!("https://{host}/slo/post"))?,
        SloEndpoint::redirect(format!("https://{host}/slo/redirect"))?,
        SloEndpoint::simple_sign(format!("https://{host}/slo/simple-sign"))?,
        SloEndpoint::soap(format!("https://{host}/slo/soap"))?,
    ])
}

fn sp_with(encryption: XmlEncryptionPolicy) -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .slo_endpoints(slo_endpoints("sp.example.com")?)
        .name_id_format(NameIdFormat::Persistent)
        .credentials(credentials())
        .xml(xml(encryption))
        .build()?,
    ))
}

fn idp_with(encryption: XmlEncryptionPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    idp_with_credentials(encryption, credentials())
}

fn idp_with_credentials(
    encryption: XmlEncryptionPolicy,
    credentials: Credentials,
) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .slo_endpoints(slo_endpoints("idp.example.com")?)
        .credentials(credentials)
        .xml(xml(encryption))
        .build()?,
    ))
}

struct Parties {
    sp: saml_rs::ServiceProvider,
    idp: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn parties_with(
    sp: saml_rs::ServiceProvider,
    idp: saml_rs::IdentityProvider,
) -> Result<Parties, Box<dyn std::error::Error>> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok(Parties {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn parties() -> Result<Parties, Box<dyn std::error::Error>> {
    parties_with(
        sp_with(XmlEncryptionPolicy::default())?,
        idp_with(XmlEncryptionPolicy::default())?,
    )
}

fn principal() -> NameId {
    NameId::new(PRINCIPAL).with_format(NameIdFormat::Persistent)
}

fn subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::new(principal()).with_session_index(SessionIndex::try_new("_session")?))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn start_options(binding: LogoutBinding) -> Result<StartSlo, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => StartSlo::post(),
        LogoutBinding::Redirect => StartSlo::redirect(),
        LogoutBinding::SimpleSign => StartSlo::simple_sign(),
        LogoutBinding::Soap => StartSlo::soap(),
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

fn respond_options(binding: LogoutBinding) -> Result<RespondSlo, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => RespondSlo::post(),
        LogoutBinding::Redirect => RespondSlo::redirect(),
        LogoutBinding::SimpleSign => RespondSlo::simple_sign(),
        LogoutBinding::Soap => RespondSlo::soap(),
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn redirect_query<Message>(outbound: &Outbound<Message>) -> Result<String, SamlError> {
    let url = outbound.redirect_url()?;
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(query.to_string())
}

fn request_input(
    outbound: &Outbound<LogoutRequest>,
    binding: LogoutBinding,
) -> Result<Inbound<LogoutRequest>, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => Inbound::post(post_fields(outbound)?),
        LogoutBinding::Redirect => Inbound::redirect(redirect_query(outbound)?),
        LogoutBinding::SimpleSign => Inbound::simple_sign(post_fields(outbound)?),
        LogoutBinding::Soap => Inbound::soap(
            outbound.soap_request()?.envelope(),
            SoapChannel::unattested(),
        ),
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

fn response_input(
    outbound: &Outbound<LogoutResponse>,
    binding: LogoutBinding,
) -> Result<Inbound<LogoutResponse>, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => Inbound::post(post_fields(outbound)?),
        LogoutBinding::Redirect => Inbound::redirect(redirect_query(outbound)?),
        LogoutBinding::SimpleSign => Inbound::simple_sign(post_fields(outbound)?),
        LogoutBinding::Soap => Inbound::soap(
            outbound.soap_response()?.envelope(),
            SoapChannel::unattested(),
        ),
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

/// The `LogoutRequest` XML that `outbound` carries.
fn request_xml(outbound: &Outbound<LogoutRequest>) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.delivery() {
        OutboundDelivery::Redirect(url) => {
            let url = Url::parse(url)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            let compressed = STANDARD.decode(encoded.as_ref())?;
            Ok(std::io::read_to_string(DeflateDecoder::new(
                compressed.as_slice(),
            ))?)
        }
        OutboundDelivery::PostForm(form) => Ok(String::from_utf8(
            STANDARD.decode(form.value("SAMLRequest").ok_or("missing SAMLRequest")?)?,
        )?),
        OutboundDelivery::SoapRequest(request) => {
            Ok(SoapBodyElement::from_envelope(request.envelope())?
                .xml()
                .to_string())
        }
        _ => Err("delivery is unsupported".into()),
    }
}

struct Sent {
    outbound: Outbound<LogoutRequest>,
    pending: saml_rs::PendingLogoutRequest,
}

fn start(parties: &Parties, initiator: Initiator, options: StartSlo) -> Result<Sent, SamlError> {
    let started = match initiator {
        Initiator::Sp => parties
            .sp
            .start_slo(&parties.idp_descriptor, subject()?, options)?,
        Initiator::Idp => parties
            .idp
            .start_slo(&parties.sp_descriptor, subject()?, options)?,
    };
    Ok(Sent {
        outbound: started.outbound,
        pending: started.pending,
    })
}

fn receive(
    parties: &Parties,
    initiator: Initiator,
    input: Inbound<LogoutRequest>,
) -> Result<Received<LogoutRequest>, SamlError> {
    match initiator {
        Initiator::Sp => parties
            .idp
            .receive_slo(&parties.sp_descriptor, input, validation()),
        Initiator::Idp => parties
            .sp
            .receive_slo(&parties.idp_descriptor, input, validation()),
    }
}

#[test]
fn encrypted_id_round_trips_on_every_binding_in_both_directions(
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = "urn:oasis:names:tc:SAML:2.0:logout:admin";
    let parties = parties()?;
    for initiator in INITIATORS {
        for binding in BINDINGS {
            let options = start_options(binding)?
                .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers)
                .reason(reason);
            let sent = start(&parties, initiator, options)?;

            let xml = request_xml(&sent.outbound)?;
            assert!(
                xml.contains("<saml:EncryptedID>"),
                "{initiator:?} {binding:?}: {xml}"
            );
            assert!(!xml.contains("NameID"), "{initiator:?} {binding:?}: {xml}");
            assert!(!xml.contains(PRINCIPAL), "{initiator:?} {binding:?}");

            let received = receive(&parties, initiator, request_input(&sent.outbound, binding)?)?;
            assert_eq!(received.message().reason(), Some(reason));
            assert_eq!(
                received.message().name_id(),
                Some(&principal()),
                "{initiator:?} {binding:?}"
            );
            assert_eq!(
                received.message().session_indexes(),
                &[SessionIndex::try_new("_session")?],
                "{initiator:?} {binding:?}"
            );

            let completed = match initiator {
                Initiator::Sp => {
                    let response = parties.idp.respond_slo(
                        &parties.sp_descriptor,
                        &received,
                        &Status::success(),
                        respond_options(binding)?,
                    )?;
                    parties.sp.finish_slo(
                        &parties.idp_descriptor,
                        &sent.pending,
                        response_input(&response, binding)?,
                        validation(),
                    )?
                }
                Initiator::Idp => {
                    let response = parties.sp.respond_slo(
                        &parties.idp_descriptor,
                        &received,
                        &Status::success(),
                        respond_options(binding)?,
                    )?;
                    parties.idp.finish_slo(
                        &parties.sp_descriptor,
                        &sent.pending,
                        response_input(&response, binding)?,
                        validation(),
                    )?
                }
            };
            let expected_issuer = match initiator {
                Initiator::Sp => IDP_ENTITY_ID,
                Initiator::Idp => SP_ENTITY_ID,
            };
            assert_eq!(
                completed.response().issuer().as_str(),
                expected_issuer,
                "{initiator:?} {binding:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn identity_provider_decrypts_an_encrypted_id_made_for_either_published_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let rolling = credentials().with_decryption_credential(X509Credential::new(
        CertificatePem::new(NEXT_CERT),
        PrivateKeyPem::new(NEXT_PRIVKEY),
    ));
    for (encryption_cert, decryption_key) in [(CERT, PRIVKEY), (NEXT_CERT, NEXT_PRIVKEY)] {
        let published = idp_with_credentials(
            XmlEncryptionPolicy::default(),
            signing_credentials().with_decryption_credential(X509Credential::new(
                CertificatePem::new(encryption_cert),
                PrivateKeyPem::new(decryption_key),
            )),
        )?;
        let parties = Parties {
            idp: idp_with_credentials(XmlEncryptionPolicy::default(), rolling.clone())?,
            ..parties_with(sp_with(XmlEncryptionPolicy::default())?, published)?
        };
        let options =
            StartSlo::post().identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
        let sent = start(&parties, Initiator::Sp, options)?;
        assert!(request_xml(&sent.outbound)?.contains("<saml:EncryptedID>"));

        let received = receive(
            &parties,
            Initiator::Sp,
            request_input(&sent.outbound, LogoutBinding::Post)?,
        )?;
        assert_eq!(received.message().name_id(), Some(&principal()));
    }
    Ok(())
}

#[test]
fn identity_provider_answers_an_encrypted_id_that_no_decryption_key_decrypts(
) -> Result<(), Box<dyn std::error::Error>> {
    let published = idp_with_credentials(
        XmlEncryptionPolicy::default(),
        signing_credentials().with_decryption_credential(X509Credential::new(
            CertificatePem::new(NEXT_CERT),
            PrivateKeyPem::new(NEXT_PRIVKEY),
        )),
    )?;
    let parties = Parties {
        idp: idp_with(XmlEncryptionPolicy::default())?,
        ..parties_with(sp_with(XmlEncryptionPolicy::default())?, published)?
    };
    let unknown_principal =
        Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal());
    for binding in BINDINGS {
        let options = start_options(binding)?
            .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
        let sent = start(&parties, Initiator::Sp, options)?;
        assert!(request_xml(&sent.outbound)?.contains("<saml:EncryptedID>"));

        let received = receive(
            &parties,
            Initiator::Sp,
            request_input(&sent.outbound, binding)?,
        )?;
        assert_eq!(received.message().name_id(), None, "{binding:?}");
        assert_eq!(
            received.message().session_indexes(),
            &[SessionIndex::try_new("_session")?],
            "{binding:?}"
        );

        let response = parties.idp.respond_slo(
            &parties.sp_descriptor,
            &received,
            &unknown_principal,
            respond_options(binding)?,
        )?;
        match parties.sp.finish_slo(
            &parties.idp_descriptor,
            &sent.pending,
            response_input(&response, binding)?,
            validation(),
        ) {
            Err(SamlError::StatusNotSuccess { status, .. }) => {
                assert_eq!(
                    status.top_level().as_uri(),
                    status_code::REQUESTER,
                    "{binding:?}"
                );
                assert_eq!(
                    status
                        .subordinate()
                        .map(saml_rs::SubordinateStatusCode::as_uri),
                    Some(status_code::UNKNOWN_PRINCIPAL),
                    "{binding:?}"
                );
            }
            other => return Err(format!("{binding:?}: unexpected {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn identity_provider_answers_a_plaintext_base_id() -> Result<(), Box<dyn std::error::Error>> {
    assert_answers_without_name_id(BASE_ID)
}

#[test]
fn idp_without_decryption_key_requires_a_single_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with(
        sp_with(XmlEncryptionPolicy::default())?,
        idp_with_credentials(XmlEncryptionPolicy::default(), signing_credentials())?,
    )?;
    let sent = start(&parties, Initiator::Sp, StartSlo::soap())?;
    let encrypted = encrypted_id(BASE_ID)?;

    let result = receive(
        &parties,
        Initiator::Sp,
        soap_request_with_identifier(&sent, &format!("{encrypted}{BASE_ID}"))?,
    );
    assert!(
        matches!(result, Err(SamlError::ProtocolProfile(_))),
        "expected ProtocolProfile for mixed identifiers, got {:?}",
        result.err()
    );
    let received = receive(
        &parties,
        Initiator::Sp,
        soap_request_with_identifier(&sent, &encrypted)?,
    )?;
    assert_eq!(received.message().name_id(), None);
    assert_eq!(
        received.message().session_indexes(),
        &[SessionIndex::try_new("_session")?]
    );
    Ok(())
}

#[test]
fn identity_provider_answers_an_encrypted_base_id() -> Result<(), Box<dyn std::error::Error>> {
    assert_answers_without_name_id(&encrypted_id(BASE_ID)?)
}

#[test]
fn logout_encrypted_id_rejects_other_saml_elements() -> Result<(), Box<dyn std::error::Error>> {
    assert_rejects_encrypted_identifier(
        r#"<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="account"/>"#,
    )
}

#[test]
fn logout_encrypted_id_rejects_base_id_from_another_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_rejects_encrypted_identifier(
        r#"<example:BaseID xmlns:example="urn:example:identifiers"/>"#,
    )
}

fn encrypted_id(plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
    let template = r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
        Type="http://www.w3.org/2001/04/xmlenc#Element">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptedKey>
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
                <xenc:CipherData><xenc:CipherValue/></xenc:CipherData>
            </xenc:EncryptedKey>
        </ds:KeyInfo>
        <xenc:CipherData><xenc:CipherValue/></xenc:CipherData>
    </xenc:EncryptedData>"#;
    let mut keys = KeysManager::new();
    saml_rs::initialize_crypto_provider()?;
    keys.add_key(load_x509_cert_pem(CERT.as_bytes())?);
    let encrypted = encrypt(&EncContext::new(keys), template, plaintext.as_bytes())?;
    Ok(format!("<saml:EncryptedID>{encrypted}</saml:EncryptedID>"))
}

fn soap_request_with_identifier(
    sent: &Sent,
    identifier: &str,
) -> Result<Inbound<LogoutRequest>, SamlError> {
    let endpoint = sent.outbound.soap_request()?.endpoint();
    let request_id = sent.outbound.id().as_str();
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0"
            IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}">
            <saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>
            {identifier}
            <samlp:SessionIndex>_session</samlp:SessionIndex>
        </samlp:LogoutRequest>"#,
        destination = endpoint.as_str(),
    );
    let request = SoapRequest::try_new(endpoint.clone(), &xml)?;
    Ok(Inbound::soap(
        request.envelope(),
        SoapChannel::mutually_authenticated_confidential(),
    ))
}

fn assert_rejects_encrypted_identifier(plaintext: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let sent = start(&parties, Initiator::Sp, StartSlo::soap())?;
    let input = soap_request_with_identifier(&sent, &encrypted_id(plaintext)?)?;
    match receive(&parties, Initiator::Sp, input) {
        Err(SamlError::ProtocolProfile(_)) => Ok(()),
        other => Err(format!(
            "expected ProtocolProfile for {plaintext}, got {:?}",
            other.err()
        )
        .into()),
    }
}

fn assert_answers_without_name_id(identifier: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let sent = start(&parties, Initiator::Sp, StartSlo::soap())?;
    let received = receive(
        &parties,
        Initiator::Sp,
        soap_request_with_identifier(&sent, identifier)?,
    )?;
    assert_eq!(received.message().name_id(), None);
    assert_eq!(
        received.message().session_indexes(),
        &[SessionIndex::try_new("_session")?]
    );

    let unknown_principal =
        Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal());
    let response = parties.idp.respond_slo(
        &parties.sp_descriptor,
        &received,
        &unknown_principal,
        RespondSlo::soap(),
    )?;
    match parties.sp.finish_slo(
        &parties.idp_descriptor,
        &sent.pending,
        response_input(&response, LogoutBinding::Soap)?,
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status, .. }) => assert_eq!(status, unknown_principal),
        other => {
            return Err(format!("expected an UnknownPrincipal response, got {other:?}").into())
        }
    }
    Ok(())
}

#[test]
fn logout_request_name_id_stays_plaintext_unless_encryption_is_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    for initiator in INITIATORS {
        for binding in BINDINGS {
            let sent = start(&parties, initiator, start_options(binding)?)?;
            let xml = request_xml(&sent.outbound)?;
            assert!(
                !xml.contains("EncryptedID"),
                "{initiator:?} {binding:?}: {xml}"
            );
            assert!(
                xml.contains(&format!(">{PRINCIPAL}</saml:NameID>")),
                "{initiator:?} {binding:?}: {xml}"
            );
        }
    }
    Ok(())
}

/// `metadata` without its `KeyDescriptor` elements.
fn without_key_descriptors(metadata: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stripped = metadata.to_string();
    while let Some(start) = stripped.find("<KeyDescriptor") {
        let end_tag = "</KeyDescriptor>";
        let end = stripped[start..]
            .find(end_tag)
            .ok_or("unterminated KeyDescriptor")?
            + start
            + end_tag.len();
        stripped.replace_range(start..end, "");
    }
    Ok(stripped)
}

#[test]
fn encrypted_id_requires_the_peer_encryption_key() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let options =
        || StartSlo::post().identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
    let idp_without_keys = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &without_key_descriptors(parties.idp.metadata_xml())?,
        MetadataTrustPolicy::Unverified,
    )?;
    let sp_without_keys = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &without_key_descriptors(parties.sp.metadata_xml())?,
        MetadataTrustPolicy::Unverified,
    )?;
    for started in [
        parties
            .sp
            .start_slo(&idp_without_keys, subject()?, options()),
        parties
            .idp
            .start_slo(&sp_without_keys, subject()?, options()),
    ] {
        match started {
            Err(SamlError::MissingMetadata(what)) => assert_eq!(what, "encryption certificate"),
            other => return Err(format!("unexpected {:?}", other.err()).into()),
        }
    }
    Ok(())
}

#[test]
fn unsigned_logout_request_with_encrypted_id_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties_with(
        sp_with(XmlEncryptionPolicy::default())?,
        idp_with(XmlEncryptionPolicy::default())?,
    )?;
    for initiator in INITIATORS {
        for binding in [LogoutBinding::Post, LogoutBinding::Redirect] {
            let options = start_options(binding)?
                .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
            let sent = start(&parties, initiator, options)?;
            assert!(request_xml(&sent.outbound)?.contains("<saml:EncryptedID>"));
            let input = match binding {
                LogoutBinding::Post => Inbound::post(unsigned_post::unsigned_post_fields(
                    &sent.outbound,
                    "SAMLRequest",
                )?),
                LogoutBinding::Redirect => {
                    let query = redirect_query(&sent.outbound)?;
                    let request = query
                        .split('&')
                        .find(|field| field.starts_with("SAMLRequest="))
                        .ok_or("missing SAMLRequest")?;
                    Inbound::redirect(request)
                }
                _ => return Err("unexpected test binding".into()),
            };
            assert!(
                matches!(
                    receive(&parties, initiator, input),
                    Err(SamlError::SignatureMissing)
                ),
                "{initiator:?} {binding:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn outstanding_logout_from_a_decrypted_name_id_rejects_a_later_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encrypted_id = XmlEncryptionPolicy::default();
    encrypted_id.identifiers = IdentifierEncryptionPolicy::EncryptIdentifiers;
    let parties = parties_with(sp_with(encrypted_id)?, idp_with(encrypted_id)?)?;
    let started_sso = parties
        .sp
        .start_sso(&parties.idp_descriptor, StartSso::post())?;
    let authn_request = parties.idp.receive_sso(
        &parties.sp_descriptor,
        Inbound::post(started_sso.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let sso_response = parties.idp.respond_sso(
        &parties.sp_descriptor,
        &authn_request,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;

    let started_slo = parties.idp.start_slo(
        &parties.sp_descriptor,
        LogoutSubject::new(principal()),
        StartSlo::redirect().identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers),
    )?;
    let received = parties.sp.receive_slo(
        &parties.idp_descriptor,
        request_input(&started_slo.outbound, LogoutBinding::Redirect)?,
        validation(),
    )?;
    let logout = received.message();
    let outstanding = OutstandingLogout::try_new(
        logout
            .name_id()
            .ok_or("decrypted LogoutRequest has no NameID")?
            .clone(),
        logout.session_indexes().to_vec(),
        logout
            .not_on_or_after()
            .ok_or("session authority LogoutRequest has no NotOnOrAfter")?
            .clone(),
    )?;

    match parties.sp.finish_sso_with_outstanding_logout(
        &parties.idp_descriptor,
        &started_sso.pending,
        Inbound::post(sso_response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
        &outstanding,
    ) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!("unexpected {:?}", other.err()).into()),
    }
}

#[test]
fn a_replayed_encrypted_id_is_rejected_before_it_is_decrypted(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    // Any attempt to decrypt fails, because this provider allows no decryption
    // work.
    let mut no_decryption_work = XmlEncryptionPolicy::default();
    no_decryption_work.max_decryption_work = 0;
    let no_decryption = idp_with(no_decryption_work)?;
    let options =
        StartSlo::post().identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
    let sent = start(&parties, Initiator::Sp, options)?;
    let mut cache = InMemoryReplayCache::with_clock(|| SystemTime::UNIX_EPOCH);
    let received = parties.idp.receive_slo(
        &parties.sp_descriptor,
        request_input(&sent.outbound, LogoutBinding::Post)?,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
            .with_replay_retention(Duration::from_secs(300)),
    )?;
    assert_eq!(received.message().name_id(), Some(&principal()));

    match no_decryption.receive_slo(
        &parties.sp_descriptor,
        request_input(&sent.outbound, LogoutBinding::Post)?,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
            .with_replay_retention(Duration::from_secs(300)),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(
                key.cache_key(),
                format!("logout_request_id:{}", sent.outbound.id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {:?}", other.err()).into()),
    }
}
