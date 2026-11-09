//! Name identifier management over SOAP, through the typed identity provider.
//!
//! The identity provider sends `ManageNameIDRequest` to a service provider and
//! reads its `ManageNameIDResponse`, and answers a service provider's request.
//! The service provider is a third-party peer: `Saml<Sp>` has no SOAP name
//! identifier management, so its messages are written here.
//!
//! Config helpers select `compatibility()` so they build without a crypto
//! provider. Name identifier management does not read that preset.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use saml_rs::{
    AcsEndpoint, EndpointUrl, EntityId, IdentifierEncryptionPolicy, Idp, IdpConfig,
    ManageNameIdService, MessageConfidentiality, MessageIntegrity, MetadataTrustPolicy, NameId,
    NameIdChange, NameIdFormat, NameIdManagementRefusal, PartyAuthentication,
    ReceivedNameIdManagement, ReplayCache, ReplayKey, ReplayPolicy, Saml, SamlError,
    SamlValidationContext, SoapChannel, SoapProtocolMessage, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, Status, SubordinateStatusCode,
};

const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const OTHER_ENTITY_ID: &str = "https://other.example.com/metadata";
const IDP_NIM_URL: &str = "https://idp.example.com/nameid";
const SP_NIM_URL: &str = "https://sp.example.com/nameid";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SOAP_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
const UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
const SP_REQUEST_ID: &str = "_sp_manage_request";

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity_provider(service: Option<&str>) -> Result<Saml<Idp>, Box<dyn std::error::Error>> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .name_id_format(NameIdFormat::Persistent)
        .validation(saml_rs::IdpValidationPolicy::compatibility());
    if let Some(location) = service {
        builder = builder
            .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(location)?));
    }
    Ok(Saml::idp(builder.build()?)?)
}

/// A service provider whose metadata publishes `services` as
/// `ManageNameIDService` endpoints, as `(binding, location)`.
fn service_provider(
    entity_id: &str,
    services: &[(&str, &str)],
) -> Result<SpDescriptor, Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(entity_id)?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )?;
    let endpoints: String = services
        .iter()
        .map(|(binding, location)| {
            format!(r#"<ManageNameIDService Binding="{binding}" Location="{location}"/>"#)
        })
        .collect();
    let metadata = sp.metadata_xml().replacen(
        "<AssertionConsumerService",
        &format!("{endpoints}<AssertionConsumerService"),
        1,
    );
    Ok(SpDescriptor::from_metadata_xml(
        &metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?)
}

fn soap_service_provider() -> Result<SpDescriptor, Box<dyn std::error::Error>> {
    service_provider(SP_ENTITY_ID, &[(SOAP_BINDING, SP_NIM_URL)])
}

fn authenticated() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Absent,
    )
}

fn validation<'a>() -> SamlValidationContext<'a> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn body(envelope: &str) -> Result<String, SamlError> {
    Ok(SoapProtocolMessage::from_envelope(envelope)?
        .xml()
        .to_string())
}

fn attribute<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = xml.find(&key)? + key.len();
    let end = xml[start..].find('"')?;
    Some(&xml[start..start + end])
}

/// A `ManageNameIDRequest` from the service provider, in a SOAP envelope.
fn sp_request_with(attributes: &str, issuer: &str, content: &str) -> Result<String, SamlError> {
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{SP_REQUEST_ID}" IssueInstant="2024-01-01T00:00:00Z" {attributes}>{issuer}{content}</samlp:ManageNameIDRequest>"#
    );
    Ok(
        SoapProtocolMessage::request(EndpointUrl::try_new(IDP_NIM_URL)?, &xml)?
            .envelope()
            .to_string(),
    )
}

fn sp_request(content: &str) -> Result<String, SamlError> {
    sp_request_with(
        &format!(r#"Version="2.0" Destination="{IDP_NIM_URL}""#),
        &format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        content,
    )
}

fn current_name_id_xml() -> String {
    format!(
        r#"<saml:NameID Format="{PERSISTENT}" NameQualifier="{IDP_ENTITY_ID}" SPNameQualifier="{SP_ENTITY_ID}">current-value</saml:NameID>"#
    )
}

/// A `ManageNameIDResponse` from the service provider, in a SOAP envelope.
fn sp_response(in_response_to: &str, issuer: &str, status: &str) -> Result<String, SamlError> {
    SoapProtocolMessage::response_envelope(&format!(
        r#"<samlp:ManageNameIDResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_sp_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status>{status}</samlp:Status></samlp:ManageNameIDResponse>"#
    ))
}

fn success_status() -> String {
    format!(r#"<samlp:StatusCode Value="{SUCCESS}"/>"#)
}

fn received_request(
    received: ReceivedNameIdManagement,
) -> Result<saml_rs::Received<saml_rs::ManageNameIdRequest>, Box<dyn std::error::Error>> {
    match received {
        ReceivedNameIdManagement::Request(request) => Ok(*request),
        ReceivedNameIdManagement::Refused(refused) => {
            Err(format!("request was refused: {:?}", refused.reason()).into())
        }
    }
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
fn identity_provider_metadata_publishes_the_soap_manage_name_id_service() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    assert!(idp.metadata_xml().contains(&format!(
        r#"<ManageNameIDService Binding="{SOAP_BINDING}" Location="{IDP_NIM_URL}"/>"#
    )));

    let without = identity_provider(None)?;
    assert!(!without.metadata_xml().contains("ManageNameIDService"));
    Ok(())
}

#[test]
fn idp_initiated_new_id_reaches_the_service_provider_and_completes() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let current = NameId::new("current-value", None);
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::NewId("new-value".into()),
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;

    let request = started.request();
    assert_eq!(request.endpoint().as_str(), SP_NIM_URL);
    assert_eq!(request.content_type(), "text/xml; charset=utf-8");
    let xml = body(request.envelope())?;
    assert!(xml.starts_with("<samlp:ManageNameIDRequest "));
    assert_eq!(attribute(&xml, "Version"), Some("2.0"));
    assert_eq!(attribute(&xml, "Destination"), Some(SP_NIM_URL));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!(
        "{}<samlp:NewID>new-value</samlp:NewID></samlp:ManageNameIDRequest>",
        current_name_id_xml()
    )));

    let request_id = attribute(&xml, "ID").ok_or("request ID is missing")?;
    started.finish(&sp_response(request_id, SP_ENTITY_ID, &success_status())?)?;
    Ok(())
}

#[test]
fn idp_initiated_termination_reaches_the_service_provider_and_completes() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let current = NameId::persistent("current-value")?;
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;

    let xml = body(started.request().envelope())?;
    assert!(xml.contains(&format!(
        "{}<samlp:Terminate/></samlp:ManageNameIDRequest>",
        current_name_id_xml()
    )));
    assert!(!xml.contains("NewID"));

    let request_id = attribute(&xml, "ID").ok_or("request ID is missing")?;
    started.finish(&sp_response(request_id, SP_ENTITY_ID, &success_status())?)?;
    Ok(())
}

#[test]
fn idp_initiated_request_keeps_the_established_qualifiers() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let current = NameId::with_qualifiers(
        "current-value",
        Some(NameIdFormat::Persistent),
        Some("https://origin-idp.example.com".into()),
        Some("https://affiliation.example.com".into()),
        Some("sp-alias".into()),
    );
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;

    let xml = body(started.request().envelope())?;
    assert!(xml.contains(&format!(
        r#"<saml:NameID Format="{PERSISTENT}" NameQualifier="https://origin-idp.example.com" SPNameQualifier="https://affiliation.example.com" SPProvidedID="sp-alias">current-value</saml:NameID>"#
    )));
    Ok(())
}

#[test]
fn a_service_provider_error_status_is_returned_to_the_caller() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let started = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;
    let request_id = attribute(&body(started.request().envelope())?, "ID")
        .ok_or("request ID is missing")?
        .to_string();
    let status = format!(
        r#"<samlp:StatusCode Value="{REQUESTER}"><samlp:StatusCode Value="{UNKNOWN_PRINCIPAL}"/></samlp:StatusCode>"#
    );

    let result = started.finish(&sp_response(&request_id, SP_ENTITY_ID, &status)?);

    assert!(matches!(
        result,
        Err(SamlError::StatusNotSuccess { top, second })
            if top == REQUESTER && second.as_deref() == Some(UNKNOWN_PRINCIPAL)
    ));
    Ok(())
}

#[test]
fn a_response_for_another_request_or_from_another_issuer_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let started = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;
    let request_id = attribute(&body(started.request().envelope())?, "ID")
        .ok_or("request ID is missing")?
        .to_string();

    assert!(matches!(
        started.finish(&sp_response("_another", SP_ENTITY_ID, &success_status())?),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    assert!(matches!(
        started.finish(&sp_response(
            &request_id,
            OTHER_ENTITY_ID,
            &success_status()
        )?),
        Err(SamlError::IssuerMismatch { .. })
    ));
    Ok(())
}

#[test]
fn a_transient_identifier_is_not_managed() -> TestResult {
    let sp = soap_service_provider()?;
    let transient_default = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .name_id_format(NameIdFormat::Transient)
            .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
                IDP_NIM_URL,
            )?))
            .validation(saml_rs::IdpValidationPolicy::compatibility())
            .build()?,
    )?;

    for (idp, current) in [
        (
            identity_provider(Some(IDP_NIM_URL))?,
            NameId::generate_transient(),
        ),
        (transient_default, NameId::new("current-value", None)),
    ] {
        let started = idp.start_name_id_management(
            &sp,
            &current,
            &NameIdChange::Terminate,
            IdentifierEncryptionPolicy::PlaintextIdentifiers,
            authenticated(),
        );
        assert!(matches!(started, Err(SamlError::ProtocolProfile(_))));
    }
    Ok(())
}

#[test]
fn a_persistent_value_longer_than_256_characters_is_not_sent() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let long = "x".repeat(257);

    for (current, change) in [
        (
            NameId::persistent("current-value")?,
            NameIdChange::NewId(long.clone()),
        ),
        (
            NameId::new(long.clone(), Some(NameIdFormat::Persistent)),
            NameIdChange::Terminate,
        ),
    ] {
        let result = idp.start_name_id_management(
            &sp,
            &current,
            &change,
            IdentifierEncryptionPolicy::PlaintextIdentifiers,
            authenticated(),
        );
        assert!(matches!(result, Err(SamlError::Invalid(_))));
    }
    Ok(())
}

#[test]
fn sp_initiated_new_id_is_received_and_answered() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!(
        "{}<samlp:NewID>sp-alias</samlp:NewID>",
        current_name_id_xml()
    ))?;

    let request = received_request(idp.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation(),
    )?)?;

    let message = request.message();
    assert_eq!(message.id().as_str(), SP_REQUEST_ID);
    assert_eq!(message.issuer().as_str(), SP_ENTITY_ID);
    assert_eq!(
        message.name_id(),
        &NameId::with_qualifiers(
            "current-value",
            Some(NameIdFormat::Persistent),
            Some(IDP_ENTITY_ID.into()),
            Some(SP_ENTITY_ID.into()),
            None,
        )
    );
    assert_eq!(message.change(), &NameIdChange::NewId("sp-alias".into()));

    let response = idp.respond_name_id_management(&sp, &request, &Status::success())?;
    assert_eq!(
        response.cache_control(),
        "no-cache, no-store, must-revalidate, private"
    );
    assert_eq!(response.pragma(), "no-cache");
    let xml = body(response.envelope())?;
    assert!(xml.starts_with("<samlp:ManageNameIDResponse "));
    assert_eq!(attribute(&xml, "InResponseTo"), Some(SP_REQUEST_ID));
    assert_eq!(attribute(&xml, "Version"), Some("2.0"));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!(
        r#"<samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status>"#
    )));
    Ok(())
}

#[test]
fn sp_initiated_termination_is_received_and_answered() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;

    let request = received_request(idp.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation(),
    )?)?;
    assert_eq!(request.message().change(), &NameIdChange::Terminate);

    let status = Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal());
    let xml = body(
        idp.respond_name_id_management(&sp, &request, &status)?
            .envelope(),
    )?;
    assert!(xml.contains(&format!(
        r#"<samlp:StatusCode Value="{REQUESTER}"><samlp:StatusCode Value="{UNKNOWN_PRINCIPAL}"/></samlp:StatusCode>"#
    )));
    Ok(())
}

#[test]
fn an_identifier_that_does_not_decrypt_is_answered_with_an_error_status() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let encrypted_id = "<saml:EncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID>";
    let new_encrypted_id = "<samlp:NewEncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></samlp:NewEncryptedID>";

    for (content, reason, status) in [
        (
            format!("{encrypted_id}<samlp:Terminate/>"),
            NameIdManagementRefusal::UndecryptableIdentifier,
            format!(
                r#"<samlp:StatusCode Value="{REQUESTER}"><samlp:StatusCode Value="{UNKNOWN_PRINCIPAL}"/></samlp:StatusCode>"#
            ),
        ),
        (
            format!("{}{new_encrypted_id}", current_name_id_xml()),
            NameIdManagementRefusal::UndecryptableNewIdentifier,
            format!(r#"<samlp:StatusCode Value="{REQUESTER}"/>"#),
        ),
    ] {
        let received = idp.receive_name_id_management(
            &sp,
            &sp_request(&content)?,
            authenticated(),
            validation(),
        )?;
        let ReceivedNameIdManagement::Refused(refused) = received else {
            return Err("an undecryptable identifier was not refused".into());
        };
        assert_eq!(refused.reason(), reason);
        let xml = body(refused.response().envelope())?;
        assert_eq!(attribute(&xml, "InResponseTo"), Some(SP_REQUEST_ID));
        assert!(xml.contains(&format!("<samlp:Status>{status}</samlp:Status>")));
    }
    Ok(())
}

#[test]
fn a_version_other_than_2_0_is_answered_with_version_mismatch() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request_with(
        r#"Version="3.0""#,
        &format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        &format!("{}<samlp:Terminate/>", current_name_id_xml()),
    )?;

    let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation())?;

    let ReceivedNameIdManagement::Refused(refused) = received else {
        return Err("a version mismatch was not refused".into());
    };
    assert_eq!(refused.reason(), NameIdManagementRefusal::VersionMismatch);
    let xml = body(refused.response().envelope())?;
    assert!(xml.contains(&format!(
        r#"<samlp:StatusCode Value="{VERSION_MISMATCH}"/>"#
    )));
    Ok(())
}

#[test]
fn an_identity_provider_without_the_service_neither_sends_nor_accepts() -> TestResult {
    let idp = identity_provider(None)?;
    let sp = soap_service_provider()?;

    let started = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    );
    assert!(
        matches!(started, Err(SamlError::MissingMetadata(name)) if name == "ManageNameIDService")
    );

    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;
    let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());
    assert!(
        matches!(received, Err(SamlError::MissingMetadata(name)) if name == "ManageNameIDService")
    );
    Ok(())
}

#[test]
fn a_service_provider_without_a_soap_service_is_not_sent_a_request() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let redirect_only = service_provider(
        SP_ENTITY_ID,
        &[(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            SP_NIM_URL,
        )],
    )?;

    let started = idp.start_name_id_management(
        &redirect_only,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    );
    assert!(
        matches!(started, Err(SamlError::MissingMetadata(name)) if name == "ManageNameIDService")
    );

    let identity_role = format!(
        r#"<IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}"><ManageNameIDService Binding="{SOAP_BINDING}" Location="https://sp.example.com/idp-role/nameid"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/idp-role/sso"/></IDPSSODescriptor><SPSSODescriptor"#
    );
    let dual_role = SpDescriptor::from_metadata_xml(
        &service_provider(SP_ENTITY_ID, &[])?
            .metadata()
            .get_metadata()
            .replacen("<SPSSODescriptor", &identity_role, 1),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = idp.start_name_id_management(
        &dual_role,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    );
    assert!(
        matches!(started, Err(SamlError::MissingMetadata(name)) if name == "ManageNameIDService")
    );
    Ok(())
}

#[test]
fn an_unauthenticated_channel_is_refused_in_both_directions() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let weak = [
        SoapChannel::new(
            PartyAuthentication::Absent,
            MessageIntegrity::Protected,
            MessageConfidentiality::Protected,
        ),
        SoapChannel::new(
            PartyAuthentication::Mutual,
            MessageIntegrity::Absent,
            MessageConfidentiality::Protected,
        ),
    ];
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;

    for channel in weak {
        let started = idp.start_name_id_management(
            &sp,
            &NameId::persistent("current-value")?,
            &NameIdChange::Terminate,
            IdentifierEncryptionPolicy::PlaintextIdentifiers,
            channel,
        );
        assert!(matches!(started, Err(SamlError::SoapChannelProtection)));
        let received = idp.receive_name_id_management(&sp, &envelope, channel, validation());
        assert!(matches!(received, Err(SamlError::SoapChannelProtection)));
    }
    Ok(())
}

#[test]
fn a_request_the_service_provider_did_not_issue_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let content = format!("{}<samlp:Terminate/>", current_name_id_xml());
    let version = format!(r#"Version="2.0" Destination="{IDP_NIM_URL}""#);

    for issuer in [
        format!("<saml:Issuer>{OTHER_ENTITY_ID}</saml:Issuer>"),
        String::new(),
    ] {
        let envelope = sp_request_with(&version, &issuer, &content)?;
        let received =
            idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());
        assert!(matches!(received, Err(SamlError::IssuerMismatch { .. })));
    }

    let non_entity = format!(
        r#"<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{SP_ENTITY_ID}</saml:Issuer>"#
    );
    let envelope = sp_request_with(&version, &non_entity, &content)?;
    let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());
    assert!(matches!(received, Err(SamlError::ProtocolProfile(_))));

    let other_sp = service_provider(OTHER_ENTITY_ID, &[(SOAP_BINDING, SP_NIM_URL)])?;
    let request = received_request(idp.receive_name_id_management(
        &sp,
        &sp_request(&content)?,
        authenticated(),
        validation(),
    )?)?;
    let answered = idp.respond_name_id_management(&other_sp, &request, &Status::success());
    assert!(matches!(answered, Err(SamlError::IssuerMismatch { .. })));
    Ok(())
}

#[test]
fn a_destination_other_than_the_receiving_endpoint_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request_with(
        r#"Version="2.0" Destination="https://idp.example.com/elsewhere""#,
        &format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        &format!("{}<samlp:Terminate/>", current_name_id_xml()),
    )?;

    let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());

    assert!(matches!(
        received,
        Err(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn a_request_without_destination_is_accepted() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request_with(
        r#"Version="2.0""#,
        &format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        &format!("{}<samlp:Terminate/>", current_name_id_xml()),
    )?;

    let request = received_request(idp.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation(),
    )?)?;

    assert_eq!(request.message().change(), &NameIdChange::Terminate);
    Ok(())
}

#[test]
fn a_replayed_request_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;
    let mut cache = MemoryReplayCache::default();

    for expected_replay in [false, true] {
        let validation =
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
                .with_replay_retention(Duration::from_secs(300));
        let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation);
        assert_eq!(
            matches!(received, Err(SamlError::ReplayDetected { .. })),
            expected_replay
        );
    }
    assert!(cache
        .seen
        .contains(&format!("manage_name_id_request_id:{SP_REQUEST_ID}")));
    Ok(())
}

#[test]
fn a_request_without_one_identifier_and_one_change_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let name_id = current_name_id_xml();

    for content in [
        name_id.clone(),
        "<samlp:Terminate/>".to_string(),
        format!("{name_id}{name_id}<samlp:Terminate/>"),
        format!("{name_id}<samlp:Terminate/><samlp:NewID>value</samlp:NewID>"),
        format!("{name_id}<saml:Terminate/>"),
        format!(
            r#"{name_id}<samlp:NewID><ext:Value xmlns:ext="urn:test">alias</ext:Value></samlp:NewID>"#
        ),
        format!("{name_id}<samlp:Terminate>now</samlp:Terminate>"),
        r#"<saml:NameID><ext:Value xmlns:ext="urn:test">alias</ext:Value></saml:NameID><samlp:Terminate/>"#
            .to_string(),
    ] {
        let received = idp.receive_name_id_management(
            &sp,
            &sp_request(&content)?,
            authenticated(),
            validation(),
        );
        assert!(
            matches!(received, Err(SamlError::ProtocolProfile(_))),
            "{content} was accepted"
        );
    }
    Ok(())
}
