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

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::deflate_raw_decode;
use saml_rs::constants::status_code;
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, CertificatePem, Credentials, EntityId, FormField, IdentifierEncryptionPolicy,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, InMemoryReplayCache, Inbound, LogoutBinding,
    LogoutPolicy, LogoutRequest, LogoutResponse, LogoutSigning, LogoutSubject, MetadataTrustPolicy,
    NameId, NameIdFormat, Outbound, OutstandingLogout, PrivateKeyPem, Received, ReplayPolicy,
    RespondSlo, RespondSso, Saml, SamlError, SamlValidationContext, SessionIndex, SloEndpoint,
    SoapChannel, SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint, StartSlo,
    StartSso, Status, SubordinateStatusCode, X509Credential, XmlEncryptionPolicy, XmlPolicy,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";
const PRINCIPAL: &str = "alice-persistent-id";

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
    XmlPolicy {
        encryption,
        ..XmlPolicy::default()
    }
}

fn slo_endpoints(host: &str) -> Result<Vec<SloEndpoint>, SamlError> {
    Ok(vec![
        SloEndpoint::post(format!("https://{host}/slo/post"))?,
        SloEndpoint::redirect(format!("https://{host}/slo/redirect"))?,
        SloEndpoint::simple_sign(format!("https://{host}/slo/simple-sign"))?,
        SloEndpoint::soap(format!("https://{host}/slo/soap"))?,
    ])
}

fn sp_with(
    logout: LogoutPolicy,
    encryption: XmlEncryptionPolicy,
) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Ok(Saml::sp(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .slo_endpoints(slo_endpoints("sp.example.com")?)
        .credentials(credentials())
        .validation(SpValidationPolicy {
            logout,
            ..SpValidationPolicy::recommended()
        })
        .xml(xml(encryption))
        .build()?,
    ))
}

fn idp_with(
    logout: LogoutPolicy,
    encryption: XmlEncryptionPolicy,
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    idp_with_credentials(logout, encryption, credentials())
}

fn idp_with_credentials(
    logout: LogoutPolicy,
    encryption: XmlEncryptionPolicy,
    credentials: Credentials,
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Ok(Saml::idp(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .slo_endpoints(slo_endpoints("idp.example.com")?)
        .credentials(credentials)
        .validation(IdpValidationPolicy {
            logout,
            ..IdpValidationPolicy::recommended()
        })
        .xml(xml(encryption))
        .build()?,
    ))
}

struct Parties {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn parties_with(
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
) -> Result<Parties, Box<dyn std::error::Error>> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
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
        sp_with(LogoutPolicy::recommended(), XmlEncryptionPolicy::default())?,
        idp_with(LogoutPolicy::recommended(), XmlEncryptionPolicy::default())?,
    )
}

fn principal() -> NameId {
    NameId::new(PRINCIPAL).with_format(NameIdFormat::Persistent)
}

fn subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::new(principal()).with_session_index(SessionIndex::try_new("_session")?))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
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
    let context = outbound.raw_context();
    match context.binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            Ok(String::from_utf8(deflate_raw_decode(
                &STANDARD.decode(encoded.as_ref())?,
            )?)?)
        }
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(STANDARD.decode(&context.context)?)?)
        }
        Binding::Soap => Ok(context.context.clone()),
        _ => Err("binding is unsupported".into()),
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
    let parties = parties()?;
    for initiator in INITIATORS {
        for binding in BINDINGS {
            let options = start_options(binding)?
                .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
            let sent = start(&parties, initiator, options)?;

            let xml = request_xml(&sent.outbound)?;
            assert!(
                xml.contains("<saml:EncryptedID>"),
                "{initiator:?} {binding:?}: {xml}"
            );
            assert!(!xml.contains("NameID"), "{initiator:?} {binding:?}: {xml}");
            assert!(!xml.contains(PRINCIPAL), "{initiator:?} {binding:?}");

            let received = receive(&parties, initiator, request_input(&sent.outbound, binding)?)?;
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
    for encryption_cert in [CERT, NEXT_CERT] {
        let published = idp_with_credentials(
            LogoutPolicy::recommended(),
            XmlEncryptionPolicy::default(),
            signing_credentials().with_decryption_credential(X509Credential::new(
                CertificatePem::new(encryption_cert),
                PrivateKeyPem::new(PRIVKEY),
            )),
        )?;
        let parties = Parties {
            idp: idp_with_credentials(
                LogoutPolicy::recommended(),
                XmlEncryptionPolicy::default(),
                rolling.clone(),
            )?,
            ..parties_with(
                sp_with(LogoutPolicy::recommended(), XmlEncryptionPolicy::default())?,
                published,
            )?
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
        LogoutPolicy::recommended(),
        XmlEncryptionPolicy::default(),
        signing_credentials().with_decryption_credential(X509Credential::new(
            CertificatePem::new(NEXT_CERT),
            PrivateKeyPem::new(PRIVKEY),
        )),
    )?;
    let parties = Parties {
        idp: idp_with(LogoutPolicy::recommended(), XmlEncryptionPolicy::default())?,
        ..parties_with(
            sp_with(LogoutPolicy::recommended(), XmlEncryptionPolicy::default())?,
            published,
        )?
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
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp_without_keys = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &without_key_descriptors(parties.sp.metadata_xml())?,
        MetadataTrustPolicy::AllowUnsigned,
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
fn unsigned_encrypted_id_stays_unread() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with(
        sp_with(
            LogoutPolicy::compatibility(),
            XmlEncryptionPolicy::default(),
        )?,
        idp_with(
            LogoutPolicy::compatibility(),
            XmlEncryptionPolicy::default(),
        )?,
    )?;
    for initiator in INITIATORS {
        for binding in [LogoutBinding::Post, LogoutBinding::Redirect] {
            let options = start_options(binding)?
                .signing(LogoutSigning::DoNotSign)
                .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers);
            let sent = start(&parties, initiator, options)?;
            assert!(request_xml(&sent.outbound)?.contains("<saml:EncryptedID>"));
            let input = request_input(&sent.outbound, binding)?;
            let received = receive(&parties, initiator, input)?;
            assert_eq!(
                received.message().name_id(),
                None,
                "{initiator:?} {binding:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn outstanding_logout_from_a_decrypted_name_id_rejects_a_later_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with(
        sp_with(
            LogoutPolicy::recommended(),
            XmlEncryptionPolicy {
                identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
                ..XmlEncryptionPolicy::default()
            },
        )?,
        idp_with(
            LogoutPolicy::recommended(),
            XmlEncryptionPolicy {
                identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
                ..XmlEncryptionPolicy::default()
            },
        )?,
    )?;
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
        validation(),
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
    // Any attempt to decrypt fails, because this decryption key does not load.
    let unloadable_key = idp_with_credentials(
        LogoutPolicy::recommended(),
        XmlEncryptionPolicy::default(),
        signing_credentials().with_decryption_credential(X509Credential::new(
            CertificatePem::new(CERT),
            PrivateKeyPem::new("not a private key"),
        )),
    )?;
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

    match unloadable_key.receive_slo(
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
