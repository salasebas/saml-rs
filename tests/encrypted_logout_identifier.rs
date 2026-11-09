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

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdentifierEncryptionPolicy, IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutBinding,
    LogoutPolicy, LogoutRequest, LogoutResponse, LogoutSigning, LogoutSubject, MetadataTrustPolicy,
    NameId, NameIdFormat, Outbound, OutstandingLogout, PrivateKeyPem, Received, ReplayPolicy,
    RespondSlo, RespondSso, Saml, SamlError, SamlValidationContext, SessionIndex, SloEndpoint,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, StartSlo, StartSso,
    Subject, XmlEncryptionPolicy, XmlPolicy,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";
const PRINCIPAL: &str = "alice-persistent-id";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

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
    let mut builder = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default());
    for endpoint in slo_endpoints("sp.example.com")? {
        builder = builder.slo_endpoint(endpoint);
    }
    Saml::sp(
        builder
            .credentials(credentials())
            .validation(SpValidationPolicy {
                logout,
                ..SpValidationPolicy::recommended()
            })
            .xml(xml(encryption))
            .build()?,
    )
}

fn idp_with(
    logout: LogoutPolicy,
    encryption: XmlEncryptionPolicy,
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO)?);
    for endpoint in slo_endpoints("idp.example.com")? {
        builder = builder.slo_endpoint(endpoint);
    }
    Saml::idp(
        builder
            .credentials(credentials())
            .validation(IdpValidationPolicy {
                logout,
                ..IdpValidationPolicy::recommended()
            })
            .xml(xml(encryption))
            .build()?,
    )
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
    NameId::new(PRINCIPAL, Some(NameIdFormat::Persistent))
}

fn subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        principal(),
        SessionIndex::try_new("_session")?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn start_options(binding: LogoutBinding) -> StartSlo {
    match binding {
        LogoutBinding::Post => StartSlo::post(),
        LogoutBinding::Redirect => StartSlo::redirect(),
        LogoutBinding::SimpleSign => StartSlo::simple_sign(),
        LogoutBinding::Soap => StartSlo::soap(),
    }
}

fn respond_options(binding: LogoutBinding) -> RespondSlo {
    match binding {
        LogoutBinding::Post => RespondSlo::post(),
        LogoutBinding::Redirect => RespondSlo::redirect(),
        LogoutBinding::SimpleSign => RespondSlo::simple_sign(),
        LogoutBinding::Soap => RespondSlo::soap(),
    }
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
) -> Result<BrowserInput<LogoutRequest>, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => BrowserInput::<LogoutRequest>::post(post_fields(outbound)?),
        LogoutBinding::Redirect => {
            BrowserInput::<LogoutRequest>::redirect(redirect_query(outbound)?)
        }
        LogoutBinding::SimpleSign => {
            BrowserInput::<LogoutRequest>::simple_sign(post_fields(outbound)?)
        }
        LogoutBinding::Soap => {
            BrowserInput::<LogoutRequest>::soap(outbound.soap_request()?.envelope())
        }
    })
}

fn response_input(
    outbound: &Outbound<LogoutResponse>,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutResponse>, SamlError> {
    Ok(match binding {
        LogoutBinding::Post => BrowserInput::<LogoutResponse>::post(post_fields(outbound)?),
        LogoutBinding::Redirect => {
            BrowserInput::<LogoutResponse>::redirect(redirect_query(outbound)?)
        }
        LogoutBinding::SimpleSign => {
            BrowserInput::<LogoutResponse>::simple_sign(post_fields(outbound)?)
        }
        LogoutBinding::Soap => {
            BrowserInput::<LogoutResponse>::soap(outbound.soap_response()?.envelope())
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
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                encoded.as_ref(),
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(base64_decode(&context.context)?)?)
        }
        Binding::Soap => Ok(context.context.clone()),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
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
    input: BrowserInput<LogoutRequest>,
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
            let options = start_options(binding)
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
                received.message().name_id().map(NameId::value),
                Some(PRINCIPAL),
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
                        respond_options(binding),
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
                        respond_options(binding),
                    )?;
                    parties.idp.finish_slo(
                        &parties.sp_descriptor,
                        &sent.pending,
                        response_input(&response, binding)?,
                        validation(),
                    )?
                }
            };
            assert!(completed.response().is_some(), "{initiator:?} {binding:?}");
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
            let sent = start(&parties, initiator, start_options(binding))?;
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
    let idp_without_keys = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &without_key_descriptors(parties.idp.metadata_xml())?,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let sp_without_keys = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &without_key_descriptors(parties.sp.metadata_xml())?,
        MetadataTrustPolicy::UnsignedForCompatibility,
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
            let options = start_options(binding)
                .signing(LogoutSigning::DoNotSignForCompatibility)
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
            XmlEncryptionPolicy::encrypt_ids(),
        )?,
        idp_with(
            LogoutPolicy::recommended(),
            XmlEncryptionPolicy::encrypt_ids(),
        )?,
    )?;
    let started_sso = parties
        .sp
        .start_sso(&parties.idp_descriptor, StartSso::post())?;
    let authn_request = parties.idp.receive_sso(
        &parties.sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started_sso.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let sso_response = parties.idp.respond_sso(
        &parties.sp_descriptor,
        &authn_request,
        Subject::new(principal(), Vec::new()),
        RespondSso::post(),
    )?;

    let started_slo = parties.idp.start_slo(
        &parties.sp_descriptor,
        LogoutSubject::from_name_id(principal()),
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
        BrowserInput::<SsoResponse>::post(sso_response.post_form()?.fields().to_vec()),
        validation(),
        &outstanding,
    ) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!("unexpected {:?}", other.err()).into()),
    }
}
