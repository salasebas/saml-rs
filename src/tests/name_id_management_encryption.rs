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

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::time::{Duration, SystemTime};

use saml_rs::binding::{append_signature, build_redirect_octet};
use saml_rs::constants::{signature_algorithm::RSA_SHA256, status_code, ParserType};
use saml_rs::crypto::{keys::read_private_key, sign_octet_string};
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    AcsEndpoint, CertificatePem, Credentials, EndpointUrl, EntityId, IdentifierEncryptionPolicy,
    IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, InMemoryReplayCache, Inbound,
    ManageNameIdRequest, ManageNameIdResponse, ManageNameIdService, MessageConfidentiality,
    MessageIntegrity, MetadataTrustPolicy, NameId, NameIdChange, NameIdFormat,
    NameIdManagementReceipt, NameIdManagementRefusal, Outbound, PartyAuthentication, PrivateKeyPem,
    ReceiveNameIdManagement, ReplayPolicy, RequestAgePolicy, RespondNameIdManagement, SamlError,
    SamlValidationContext, ServiceProvider, SoapBodyElement, SoapChannel, SoapRequest, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, StartNameIdManagement, Status, X509Credential,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_MANAGE: &str = "https://sp.example.com/manage-name-id";
const IDP_MANAGE: &str = "https://idp.example.com/manage-name-id";
const IDP_MANAGE_SOAP: &str = "https://idp.example.com/manage-name-id/soap";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

const SIGNING_KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SIGNING_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const SP_DECRYPTION_KEY: &str =
    include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_ENCRYPTION_CERT: &str =
    include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const IDP_DECRYPTION_KEY: &str =
    include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_ENCRYPTION_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
const IDP_NEXT_DECRYPTION_KEY: &str =
    include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const IDP_NEXT_ENCRYPTION_CERT: &str =
    include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const EC_CERT: &str = include_str!("../../tests/fixtures/key/prime256v1/cert.pem");

fn credentials(encryption_cert: &str, decryption_key: &str) -> Credentials {
    Credentials::default()
        .with_signing_credential(X509Credential::new(
            CertificatePem::new(SIGNING_CERT),
            PrivateKeyPem::new(SIGNING_KEY),
        ))
        .with_decryption_credential(X509Credential::new(
            CertificatePem::new(encryption_cert),
            PrivateKeyPem::new(decryption_key),
        ))
}

fn encrypted() -> StartNameIdManagement {
    StartNameIdManagement::new()
        .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers)
}

fn sp_with(
    encryption_cert: &str,
    decryption_key: &str,
) -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .manage_name_id_redirect_service(EndpointUrl::try_new(SP_MANAGE)?)
        .credentials(credentials(encryption_cert, decryption_key))
        .validation(SpValidationPolicy::default())
        .build()?,
    ))
}

fn sp() -> Result<saml_rs::ServiceProvider, SamlError> {
    sp_with(SP_ENCRYPTION_CERT, SP_DECRYPTION_KEY)
}

fn sp_descriptor_with_foreign_encryption_certificate() -> Result<SpDescriptor, SamlError> {
    sp_descriptor(&sp_with(IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY)?)
}

fn idp() -> Result<saml_rs::IdentityProvider, SamlError> {
    idp_with(credentials(IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY))
}

fn idp_with(credentials: Credentials) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
            IDP_MANAGE,
        )?))
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_MANAGE_SOAP,
        )?))
        .credentials(credentials)
        .validation(IdpValidationPolicy::default())
        .build()?,
    ))
}

fn sp_descriptor(sp: &saml_rs::ServiceProvider) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )
}

fn idp_descriptor_from(metadata: &str) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        metadata,
        MetadataTrustPolicy::Unverified,
    )
}

fn idp_descriptor(idp: &saml_rs::IdentityProvider) -> Result<IdpDescriptor, SamlError> {
    idp_descriptor_from(idp.metadata_xml())
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn alice() -> NameId {
    NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
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
) -> Result<Inbound<ManageNameIdRequest>, SamlError> {
    Ok(Inbound::redirect(redirect_query(outbound)?))
}

fn response_input(
    outbound: &Outbound<ManageNameIdResponse>,
) -> Result<Inbound<ManageNameIdResponse>, SamlError> {
    Ok(Inbound::redirect(redirect_query(outbound)?))
}

fn redirect_message_xml<Message>(
    outbound: &Outbound<Message>,
) -> Result<String, Box<dyn std::error::Error>> {
    let query = redirect_query(outbound)?;
    let encoded = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "SAMLRequest" || name == "SAMLResponse")
        .map(|(_, value)| value.into_owned())
        .ok_or("redirect URL carries no SAML message")?;
    let deflated = STANDARD.decode(&encoded)?;
    Ok(String::from_utf8(saml_rs::binding::deflate_raw_decode(
        &deflated,
        saml_rs::binding::MAX_DEFLATE_RAW_DECODE_BYTES,
    )?)?)
}

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

fn idp_request_input(content: &str) -> Result<Inbound<ManageNameIdRequest>, SamlError> {
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_manage1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{SP_MANAGE}"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>{content}</samlp:ManageNameIDRequest>"#
    );
    let key = read_private_key(SIGNING_KEY, None)?;
    let octet = build_redirect_octet(ParserType::ManageNameIdRequest, &xml, None, RSA_SHA256)?;
    let signature = sign_octet_string(&octet, &key, RSA_SHA256)?;
    let url = append_signature(SP_MANAGE, &octet, &signature)?;
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(Inbound::redirect(query))
}

fn authenticated() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Unattested,
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

    let NameIdManagementReceipt::Request(request) = sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::new(),
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
        &Status::success(),
        RespondNameIdManagement::new(),
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

    let NameIdManagementReceipt::Request(request) = idp.receive_name_id_management_redirect(
        &sp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::new(),
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
        &Status::success(),
        RespondNameIdManagement::new(),
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
    let idp = idp_with(
        credentials(IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY).with_decryption_credential(
            X509Credential::new(
                CertificatePem::new(IDP_NEXT_ENCRYPTION_CERT),
                PrivateKeyPem::new(IDP_NEXT_DECRYPTION_KEY),
            ),
        ),
    )?;
    for (encryption_cert, decryption_key) in [
        (IDP_ENCRYPTION_CERT, IDP_DECRYPTION_KEY),
        (IDP_NEXT_ENCRYPTION_CERT, IDP_NEXT_DECRYPTION_KEY),
    ] {
        let published = idp_with(credentials(encryption_cert, decryption_key))?;
        let started = sp.start_name_id_management_redirect(
            &idp_descriptor(&published)?,
            &alice(),
            &NameIdChange::NewId("sp-alias".into()),
            encrypted(),
        )?;
        encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;

        let NameIdManagementReceipt::Request(request) = idp.receive_name_id_management_redirect(
            &sp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::new(),
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

fn with_unusable_encryption_key_first(
    metadata: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let first_encryption_key = metadata
        .find("<KeyDescriptor use=\"encryption\"")
        .ok_or("metadata publishes no encryption key")?;
    let mut metadata = metadata.to_string();
    metadata.insert_str(
        first_encryption_key,
        &format!(
            "<KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>",
            normalize_cert_string(EC_CERT)
        ),
    );
    Ok(metadata)
}

#[test]
fn identifiers_are_encrypted_for_a_later_peer_key_the_key_transport_can_use() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let sp_peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &with_unusable_encryption_key_first(sp.metadata_xml())?,
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_peer = idp_descriptor_from(&with_unusable_encryption_key_first(idp.metadata_xml())?)?;

    let started = sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::NewId("sp-alias".into()),
        encrypted(),
    )?;
    encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;
    let NameIdManagementReceipt::Request(request) = idp.receive_name_id_management_redirect(
        &sp_descriptor(&sp)?,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::new(),
        validation(),
    )?
    else {
        return Err("the service provider request was refused".into());
    };
    assert_eq!(request.message().name_id(), &alice());

    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::NewId("alice-2".into()),
        encrypted(),
    )?;
    encrypted_identifier_and_new_value(&redirect_message_xml(&started.outbound)?)?;
    let NameIdManagementReceipt::Request(request) = sp.receive_name_id_management_redirect(
        &idp_descriptor(&idp)?,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::new(),
        validation(),
    )?
    else {
        return Err("the identity provider request was refused".into());
    };
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("alice-2".into())
    );
    Ok(())
}

#[test]
fn identity_provider_encrypts_a_soap_request_and_decrypts_one_over_soap() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let sp_soap_peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp.metadata_xml().replacen(
            "<ManageNameIDService ",
            r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://sp.example.com/manage-name-id/soap"/><ManageNameIDService "#,
            1,
        ),
        MetadataTrustPolicy::Unverified,
    )?;

    let started = idp.start_name_id_management(
        &sp_soap_peer,
        &alice(),
        &NameIdChange::NewId("alice-2".into()),
        StartNameIdManagement::new()
            .identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers),
        authenticated(),
    )?;
    let soap_xml = SoapBodyElement::from_envelope(started.request().envelope())?
        .xml()
        .to_string();
    let (encrypted_id, new_encrypted_id) = encrypted_identifier_and_new_value(&soap_xml)?;
    let NameIdManagementReceipt::Request(request) = sp.receive_name_id_management_redirect(
        &idp_peer,
        idp_request_input(&format!("{encrypted_id}{new_encrypted_id}"))?,
        ReceiveNameIdManagement::new(),
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

    let redirect = sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::NewId("sp-alias".into()),
        encrypted(),
    )?;
    let redirect_xml = redirect_message_xml(&redirect.outbound)?;
    let (encrypted_id, new_encrypted_id) = encrypted_identifier_and_new_value(&redirect_xml)?;
    let envelope = SoapRequest::try_new(
        EndpointUrl::try_new(IDP_MANAGE_SOAP)?,
        &format!(
            r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_sp_soap" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>{encrypted_id}{new_encrypted_id}</samlp:ManageNameIDRequest>"#
        ),
    )?;
    let NameIdManagementReceipt::Request(request) = idp.receive_name_id_management(
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
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (
        sp_descriptor_with_foreign_encryption_certificate()?,
        idp_descriptor(&idp)?,
    );
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;

    let NameIdManagementReceipt::Refused(refused) = sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::new(),
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
        matches!(refused.decryption_error(), Some(SamlError::Crypto { .. })),
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
        Err(SamlError::StatusNotSuccess { status, .. })
            if status.top_level().as_uri() == status_code::REQUESTER
                && status
                    .subordinate()
                    .map(saml_rs::SubordinateStatusCode::as_uri)
                    == Some(status_code::UNKNOWN_PRINCIPAL) => {}
        other => return Err(format!("expected Requester/UnknownPrincipal, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_replayed_or_stale_request_is_rejected_before_its_identifier_is_decrypted() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (
        sp_descriptor_with_foreign_encryption_certificate()?,
        idp_descriptor(&idp)?,
    );
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;
    let receive = |now: SystemTime, cache: &mut InMemoryReplayCache| {
        sp.receive_name_id_management_redirect(
            &idp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::new(),
            SamlValidationContext::new(now, ReplayPolicy::RequireCache(cache))
                .with_replay_retention(Duration::from_secs(300))
                .with_manage_name_id_request_age(RequestAgePolicy::Bounded {
                    max_age: Duration::from_secs(60),
                }),
        )
    };

    let mut cache = InMemoryReplayCache::with_clock(|| SystemTime::UNIX_EPOCH);
    let NameIdManagementReceipt::Refused(_) = receive(SystemTime::now(), &mut cache)? else {
        return Err("an identifier that does not decrypt was not refused".into());
    };
    match receive(SystemTime::now(), &mut cache) {
        Err(SamlError::ReplayDetected { .. }) => {}
        other => return Err(format!("expected ReplayDetected, got {other:?}").into()),
    }

    let stale = SystemTime::now() + Duration::from_secs(60 * 60);
    match receive(
        stale,
        &mut InMemoryReplayCache::with_clock(|| SystemTime::UNIX_EPOCH),
    ) {
        Ok(NameIdManagementReceipt::Refused(refused)) => {
            assert_eq!(
                refused.reason(),
                NameIdManagementRefusal::RequestAgeOutsideWindow
            );
            assert!(refused.decryption_error().is_none());
            Ok(())
        }
        other => Err(format!("expected a request age refusal, got {other:?}").into()),
    }
}

#[test]
fn the_answer_to_a_refused_request_goes_to_an_http_endpoint_only_when_allowed() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let http_idp_peer = idp_descriptor_from(
        &idp.metadata_xml()
            .replace(IDP_MANAGE, "http://idp.example.com/manage-name-id"),
    )?;
    let started = idp.start_name_id_management_redirect(
        &sp_descriptor_with_foreign_encryption_certificate()?,
        &alice(),
        &NameIdChange::Terminate,
        encrypted(),
    )?;
    let input =
        || -> Result<Inbound<ManageNameIdRequest>, SamlError> { request_input(&started.outbound) };

    match sp.receive_name_id_management_redirect(
        &http_idp_peer,
        input()?,
        ReceiveNameIdManagement::new(),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => return Err(format!("expected an https rejection, got {other:?}").into()),
    }

    let NameIdManagementReceipt::Refused(refused) = sp.receive_name_id_management_redirect(
        &http_idp_peer,
        input()?,
        ReceiveNameIdManagement::new().allow_http(),
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
