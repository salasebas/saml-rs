//! `EncryptedID` and `NewEncryptedID` in name identifier management, through
//! the typed identity-provider and service-provider flows.
//!
//! SAML Core §3.6.1 and Conformance Requirements §3.4. Errata 05 E12: the
//! encrypted content of `NewEncryptedID` is a `NewID`. Each provider has its
//! own encryption key pair, so a request reaches its peer only when it is
//! encrypted for that peer.
//!
//! FIPS rejects the SHA-1 RSA-OAEP key transport these tests use.
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use saml_rs::binding::{append_signature, build_redirect_octet};
use saml_rs::constants::{signature_algorithm::RSA_SHA256, status_code, ParserType};
use saml_rs::crypto::{construct_message_signature, keys::load_private_key};
use saml_rs::error::TimeWindowField;
use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, Credentials, DecryptionCredential, EndpointUrl,
    EntityId, IdentifierEncryptionPolicy, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    ManageNameIdRequest, ManageNameIdRequestAgePolicy, ManageNameIdResponse, ManageNameIdService,
    MessageConfidentiality, MessageIntegrity, MetadataTrustPolicy, NameId, NameIdChange,
    NameIdFormat, NameIdManagementRefusal, Outbound, PartyAuthentication, PrivateKeyPem,
    ReceiveNameIdManagement, ReceivedNameIdManagement, ReplayCache, ReplayKey, ReplayPolicy,
    RespondNameIdManagement, Saml, SamlError, SamlValidationContext, SoapChannel,
    SoapProtocolMessage, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
    StartNameIdManagement,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_MANAGE: &str = "https://sp.example.com/manage-name-id";
const IDP_MANAGE: &str = "https://idp.example.com/manage-name-id";
const IDP_MANAGE_SOAP: &str = "https://idp.example.com/manage-name-id/soap";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

const SIGNING_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SIGNING_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const SP_DECRYPTION_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_ENCRYPTION_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const IDP_DECRYPTION_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_ENCRYPTION_CERT: &str = include_str!("fixtures/key/idp/cert.cer");
const IDP_NEXT_DECRYPTION_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const IDP_NEXT_ENCRYPTION_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn credentials(encryption_cert: &str, decryption_key: &str) -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(SIGNING_KEY)),
        signing_certificate: Some(CertificatePem::new(SIGNING_CERT)),
        encryption_certificate: Some(CertificatePem::new(encryption_cert)),
        decryption_key: Some(PrivateKeyPem::new(decryption_key)),
        ..Credentials::default()
    }
}

fn encrypted() -> StartNameIdManagement {
    StartNameIdManagement::redirect()
        .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers)
}

/// A service provider that publishes `encryption_cert` and decrypts with its
/// own key.
fn sp_publishing(encryption_cert: &str) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                SP_MANAGE,
            )?))
            .credentials(credentials(encryption_cert, SP_DECRYPTION_KEY))
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )
}

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    sp_publishing(SP_ENCRYPTION_CERT)
}

fn idp() -> Result<Saml<saml_rs::Idp>, SamlError> {
    idp_with(credentials(IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY))
}

fn idp_with(credentials: Credentials) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                IDP_MANAGE,
            )?))
            .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
                IDP_MANAGE_SOAP,
            )?))
            .credentials(credentials)
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )
}

fn sp_descriptor(sp: &Saml<saml_rs::Sp>) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn idp_descriptor_from(metadata: &str) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn idp_descriptor(idp: &Saml<saml_rs::Idp>) -> Result<IdpDescriptor, SamlError> {
    idp_descriptor_from(idp.metadata_xml())
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn alice() -> NameId {
    NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress))
}

fn redirect_query<Message>(outbound: &Outbound<Message>) -> Result<String, SamlError> {
    let url = outbound.redirect_url()?;
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(query.to_string())
}

fn request_input(
    outbound: &Outbound<ManageNameIdRequest>,
) -> Result<BrowserInput<ManageNameIdRequest>, SamlError> {
    Ok(BrowserInput::<ManageNameIdRequest>::redirect(
        redirect_query(outbound)?,
    ))
}

fn response_input(
    outbound: &Outbound<ManageNameIdResponse>,
) -> Result<BrowserInput<ManageNameIdResponse>, SamlError> {
    Ok(BrowserInput::<ManageNameIdResponse>::redirect(
        redirect_query(outbound)?,
    ))
}

/// The SAML message XML carried by an HTTP-Redirect browser action.
fn redirect_message_xml<Message>(
    outbound: &Outbound<Message>,
) -> Result<String, Box<dyn std::error::Error>> {
    let query = redirect_query(outbound)?;
    let encoded = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "SAMLRequest" || name == "SAMLResponse")
        .map(|(_, value)| value.into_owned())
        .ok_or("redirect URL carries no SAML message")?;
    let deflated = saml_rs::binding::base64_decode(&encoded)?;
    Ok(String::from_utf8(saml_rs::binding::deflate_raw_decode(
        &deflated,
    )?)?)
}

/// The `<{qualified_name}>` element of `xml`.
fn element<'a>(xml: &'a str, qualified_name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let start = xml
        .find(&format!("<{qualified_name}>"))
        .ok_or_else(|| format!("missing {qualified_name}"))?;
    let end_tag = format!("</{qualified_name}>");
    let end = xml[start..]
        .find(&end_tag)
        .ok_or_else(|| format!("missing {qualified_name} end"))?;
    Ok(&xml[start..start + end + end_tag.len()])
}

/// The encrypted identifier and new value of a generated request.
fn encrypted_identifier_and_new_value(
    xml: &str,
) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    assert!(!xml.contains("<saml:NameID"), "{xml}");
    assert!(!xml.contains("<samlp:NewID"), "{xml}");
    assert!(!xml.contains("alice"), "{xml}");
    Ok((
        element(xml, "saml:EncryptedID")?,
        element(xml, "samlp:NewEncryptedID")?,
    ))
}

/// A `ManageNameIDRequest` from the identity provider to the service
/// provider, signed for HTTP-Redirect.
fn idp_request_input(content: &str) -> Result<BrowserInput<ManageNameIdRequest>, SamlError> {
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_manage1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{SP_MANAGE}"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>{content}</samlp:ManageNameIDRequest>"#
    );
    let key = load_private_key(SIGNING_KEY, None)?;
    let octet = build_redirect_octet(ParserType::ManageNameIdRequest, &xml, None, RSA_SHA256)?;
    let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
    let url = append_signature(SP_MANAGE, &octet, &signature);
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(BrowserInput::<ManageNameIdRequest>::redirect(query))
}

fn authenticated() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Absent,
    )
}

#[test]
fn identity_provider_encrypts_the_identifier_and_new_value_for_the_service_provider() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);

    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::NewId("alice-2".into()),
        encrypted(),
    )?;
    encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;

    let ReceivedNameIdManagement::Request(request) = sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?
    else {
        return Err("the encrypted request was refused".into());
    };
    assert_eq!(request.message().name_id(), &alice());
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("alice-2".into())
    );

    let response = sp.respond_name_id_management_redirect(
        &idp_peer,
        &request,
        RespondNameIdManagement::redirect(),
    )?;
    idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        response_input(&response)?,
        validation(),
    )?;
    Ok(())
}

#[test]
fn service_provider_encrypts_the_identifier_and_new_value_for_the_identity_provider() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);

    let started = sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::NewId("sp-alias".into()),
        encrypted(),
    )?;
    encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;

    let ReceivedNameIdManagement::Request(request) = idp.receive_name_id_management_redirect(
        &sp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?
    else {
        return Err("the encrypted request was refused".into());
    };
    assert_eq!(request.message().name_id(), &alice());
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("sp-alias".into())
    );

    let response = idp.respond_name_id_management_redirect(
        &sp_peer,
        &request,
        RespondNameIdManagement::redirect(),
    )?;
    sp.finish_name_id_management_redirect(
        &idp_peer,
        &started.pending,
        response_input(&response)?,
        validation(),
    )?;
    Ok(())
}

#[test]
fn identity_provider_decrypts_identifiers_made_for_either_published_certificate() -> TestResult {
    let sp = sp()?;
    let sp_peer = sp_descriptor(&sp)?;
    let idp = idp_with(Credentials {
        additional_decryption_keys: vec![DecryptionCredential {
            certificate: CertificatePem::new(IDP_NEXT_ENCRYPTION_CERT),
            key: PrivateKeyPem::new(IDP_NEXT_DECRYPTION_KEY),
            passphrase: None,
        }],
        ..credentials(IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY)
    })?;
    for encryption_cert in [IDP_ENCRYPTION_CERT, IDP_NEXT_ENCRYPTION_CERT] {
        let published = idp_with(credentials(encryption_cert, IDP_DECRYPTION_KEY))?;
        let started = sp.start_name_id_management_redirect(
            &idp_descriptor(&published)?,
            &alice(),
            &NameIdChange::NewId("sp-alias".into()),
            encrypted(),
        )?;
        encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;

        let ReceivedNameIdManagement::Request(request) = idp.receive_name_id_management_redirect(
            &sp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::redirect(),
            validation(),
        )?
        else {
            return Err("the encrypted request was refused".into());
        };
        assert_eq!(request.message().name_id(), &alice());
        assert_eq!(
            request.message().change(),
            &NameIdChange::NewId("sp-alias".into())
        );
    }
    Ok(())
}

#[test]
fn identity_provider_encrypts_a_soap_request_and_decrypts_one_over_soap() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let sp_soap_peer = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp.metadata_xml().replacen(
            "<ManageNameIDService ",
            r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://sp.example.com/manage-name-id/soap"/><ManageNameIDService "#,
            1,
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    // The service provider reads the elements the identity provider sends over SOAP.
    let started = idp.start_name_id_management(
        &sp_soap_peer,
        &alice(),
        &NameIdChange::NewId("alice-2".into()),
        IdentifierEncryptionPolicy::EncryptIdentifiers,
        authenticated(),
    )?;
    let soap_xml = SoapProtocolMessage::from_envelope(started.request().envelope())?
        .xml()
        .to_string();
    let (encrypted_id, new_encrypted_id) = encrypted_identifier_and_new_value(&soap_xml)?;
    let ReceivedNameIdManagement::Request(request) = sp.receive_name_id_management_redirect(
        &idp_peer,
        idp_request_input(&format!("{encrypted_id}{new_encrypted_id}"))?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?
    else {
        return Err("the elements of the SOAP request were refused".into());
    };
    assert_eq!(request.message().name_id(), &alice());
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("alice-2".into())
    );

    // The identity provider decrypts the elements a service provider sends over SOAP.
    let redirect = sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::NewId("sp-alias".into()),
        encrypted(),
    )?;
    let redirect_xml = redirect_message_xml(&redirect.outbound)?;
    let (encrypted_id, new_encrypted_id) = encrypted_identifier_and_new_value(&redirect_xml)?;
    let envelope = SoapProtocolMessage::request(
        EndpointUrl::try_new(IDP_MANAGE_SOAP)?,
        &format!(
            r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_sp_soap" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>{encrypted_id}{new_encrypted_id}</samlp:ManageNameIDRequest>"#
        ),
    )?;
    let ReceivedNameIdManagement::Request(request) = idp.receive_name_id_management(
        &sp_peer,
        envelope.envelope(),
        authenticated(),
        validation(),
    )?
    else {
        return Err("the encrypted SOAP request was refused".into());
    };
    assert_eq!(request.message().name_id(), &alice());
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("sp-alias".into())
    );
    Ok(())
}

#[test]
fn an_identifier_encrypted_for_another_key_is_answered_with_unknown_principal() -> TestResult {
    // The service provider publishes a certificate whose key it does not hold.
    let sp = sp_publishing(IDP_ENCRYPTION_CERT)?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;

    let ReceivedNameIdManagement::Refused(refused) = sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?
    else {
        return Err("an identifier that does not decrypt was not refused".into());
    };
    assert_eq!(
        refused.reason(),
        NameIdManagementRefusal::UndecryptableIdentifier
    );
    assert!(refused.response().redirect_url()?.starts_with(IDP_MANAGE));
    assert!(
        matches!(refused.decryption_error(), Some(SamlError::Crypto(_))),
        "{:?}",
        refused.decryption_error()
    );

    let error = idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        response_input(refused.response())?,
        validation(),
    );
    match error {
        Err(SamlError::StatusNotSuccess { top, second })
            if top == status_code::REQUESTER
                && second.as_deref() == Some(status_code::UNKNOWN_PRINCIPAL) => {}
        other => return Err(format!("expected Requester/UnknownPrincipal, got {other:?}").into()),
    }
    Ok(())
}

#[derive(Default)]
struct MemoryReplayCache {
    seen: HashSet<String>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        _expires_at: SystemTime,
    ) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        if !self.seen.insert(cache_key.clone()) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        Ok(())
    }
}

#[test]
fn a_replayed_or_stale_request_is_rejected_before_its_identifier_is_decrypted() -> TestResult {
    // The service provider publishes a certificate whose key it does not hold.
    let sp = sp_publishing(IDP_ENCRYPTION_CERT)?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;
    let receive = |now: SystemTime, cache: &mut MemoryReplayCache| {
        sp.receive_name_id_management_redirect(
            &idp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::redirect(),
            SamlValidationContext::new(now, ReplayPolicy::RequireCache(cache))
                .with_replay_retention(Duration::from_secs(300))
                .with_manage_name_id_request_age(ManageNameIdRequestAgePolicy::Bounded {
                    max_age: Duration::from_secs(60),
                }),
        )
    };

    let mut cache = MemoryReplayCache::default();
    let ReceivedNameIdManagement::Refused(_) = receive(SystemTime::now(), &mut cache)? else {
        return Err("an identifier that does not decrypt was not refused".into());
    };
    match receive(SystemTime::now(), &mut cache) {
        Err(SamlError::ReplayDetected { .. }) => {}
        other => return Err(format!("expected ReplayDetected, got {other:?}").into()),
    }

    let stale = SystemTime::now() + Duration::from_secs(60 * 60);
    match receive(stale, &mut MemoryReplayCache::default()) {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::ManageNameIdRequestIssueInstant,
        }) => Ok(()),
        other => Err(format!("expected a request age error, got {other:?}").into()),
    }
}

#[test]
fn the_answer_to_a_refused_request_goes_to_an_http_endpoint_only_when_allowed() -> TestResult {
    let sp = sp_publishing(IDP_ENCRYPTION_CERT)?;
    let idp = idp()?;
    let http_idp_peer = idp_descriptor_from(
        &idp.metadata_xml()
            .replace(IDP_MANAGE, "http://idp.example.com/manage-name-id"),
    )?;
    let started = idp.start_name_id_management_redirect(
        &sp_descriptor(&sp)?,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;
    let input = || -> Result<BrowserInput<ManageNameIdRequest>, SamlError> {
        request_input(&started.outbound)
    };

    match sp.receive_name_id_management_redirect(
        &http_idp_peer,
        input()?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => return Err(format!("expected an https rejection, got {other:?}").into()),
    }

    let ReceivedNameIdManagement::Refused(refused) = sp.receive_name_id_management_redirect(
        &http_idp_peer,
        input()?,
        ReceiveNameIdManagement::redirect().allow_http_name_id_management(),
        validation(),
    )?
    else {
        return Err("an identifier that does not decrypt was not refused".into());
    };
    assert!(refused
        .response()
        .redirect_url()?
        .starts_with("http://idp.example.com/manage-name-id?"));
    Ok(())
}
