#[path = "name_id_management/schema_validation.rs"]
mod schema_validation;

#[path = "common/replay_cache.rs"]
mod replay_cache;

#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

#[path = "common/tag_prefixes.rs"]
mod tag_prefixes;

use policies_without_crypto::sp_validation_without_crypto;

use replay_cache::RecordingReplayCache;

use std::time::{Duration, SystemTime};

use saml_rs::{
    AcsEndpoint, EndpointUrl, EntityId, IdentityProvider, IdpConfig, ManageNameIdService,
    MessageConfidentiality, MessageIntegrity, MetadataTrustPolicy, NameId, NameIdChange,
    NameIdFormat, NameIdManagementReceipt, NameIdManagementRefusal, PartyAuthentication,
    RelayState, ReplayPolicy, RequestAgePolicy, SamlError, SamlValidationContext, ServiceProvider,
    SoapBodyElement, SoapChannel, SoapRequest, SoapResponse, SpConfig, SpDescriptor, SsoEndpoint,
    StartNameIdManagement, Status, SubordinateStatusCode,
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
const EXTENSIONS: &str = r#"<samlp:Extensions><ext:Data xmlns:ext="urn:test"/></samlp:Extensions>"#;
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity_provider(
    service: Option<&str>,
) -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    identity_provider_with_templates(service, Default::default())
}

fn identity_provider_with_templates(
    service: Option<&str>,
    templates: saml_rs::TemplatePolicy,
) -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    let mut builder = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .templates(templates)
    .name_id_format(NameIdFormat::Persistent);
    if let Some(location) = service {
        builder = builder
            .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(location)?));
    }
    Ok(IdentityProvider::new(builder.build()?))
}

fn service_provider(
    entity_id: &str,
    services: &[(&str, &str)],
) -> Result<SpDescriptor, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(entity_id)?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .build()?,
    );
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
        EntityId::try_new(entity_id)?,
        &metadata,
        MetadataTrustPolicy::Unverified,
    )?)
}

fn soap_service_provider() -> Result<SpDescriptor, Box<dyn std::error::Error>> {
    service_provider(SP_ENTITY_ID, &[(SOAP_BINDING, SP_NIM_URL)])
}

fn authenticated() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Unattested,
    )
}

fn validation<'a>() -> SamlValidationContext<'a> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn body(envelope: &str) -> Result<String, SamlError> {
    Ok(SoapBodyElement::from_envelope(envelope)?.xml().to_string())
}

fn attribute<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = xml.find(&key)? + key.len();
    let end = xml[start..].find('"')?;
    Some(&xml[start..start + end])
}

fn sp_request_with(attributes: &str, issuer: &str, content: &str) -> Result<String, SamlError> {
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{SP_REQUEST_ID}" IssueInstant="2024-01-01T00:00:00Z" {attributes}>{issuer}{content}</samlp:ManageNameIDRequest>"#
    );
    Ok(
        SoapRequest::try_new(EndpointUrl::try_new(IDP_NIM_URL)?, &xml)?
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

fn sp_response(in_response_to: &str, issuer: &str, status: &str) -> Result<String, SamlError> {
    Ok(SoapResponse::try_new(&format!(
        r#"<samlp:ManageNameIDResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_sp_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status>{status}</samlp:Status></samlp:ManageNameIDResponse>"#
    ))?
    .envelope()
    .to_string())
}

fn success_status() -> String {
    format!(r#"<samlp:StatusCode Value="{SUCCESS}"/>"#)
}

fn received_request(
    received: NameIdManagementReceipt,
) -> Result<saml_rs::Received<saml_rs::ManageNameIdRequest>, Box<dyn std::error::Error>> {
    match received {
        NameIdManagementReceipt::Request(request) => Ok(*request),
        NameIdManagementReceipt::Refused(refused) => {
            Err(format!("request was refused: {:?}", refused.reason()).into())
        }
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
    let idp =
        identity_provider_with_templates(Some(IDP_NIM_URL), tag_prefixes::templates("p", "a"))?;
    let sp = soap_service_provider()?;
    let current = NameId::new("current-value");
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::NewId("new-value".into()),
        StartNameIdManagement::new(),
        authenticated(),
    )?;

    let request = started.request();
    assert_eq!(request.endpoint().as_str(), SP_NIM_URL);
    assert!(request.headers().iter().any(
        |header| header.name() == "Content-Type" && header.value() == "text/xml; charset=utf-8"
    ));
    let xml = body(request.envelope())?;
    assert!(xml.starts_with("<p:ManageNameIDRequest "));
    assert_eq!(attribute(&xml, "Version"), Some("2.0"));
    assert_eq!(attribute(&xml, "Destination"), Some(SP_NIM_URL));
    assert!(xml.contains(&format!("<a:Issuer>{IDP_ENTITY_ID}</a:Issuer>")));
    assert!(xml.contains(&format!(
        "{}<p:NewID>new-value</p:NewID></p:ManageNameIDRequest>",
        current_name_id_xml().replace("saml:", "a:")
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
        StartNameIdManagement::new(),
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
fn a_relay_state_is_not_sent_over_soap() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let result = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        StartNameIdManagement::new().relay_state(RelayState::try_new("state")?),
        authenticated(),
    );
    assert!(
        matches!(result, Err(SamlError::ProtocolProfile(_))),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn idp_initiated_request_qualifies_a_persistent_format_written_with_whitespace() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let format = format!(" {PERSISTENT}\n");
    let current = NameId::new("current-value").with_format(NameIdFormat::Custom(format.clone()));
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
        authenticated(),
    )?;

    let xml = body(started.request().envelope())?;
    assert_eq!(attribute(&xml, "NameQualifier"), Some(IDP_ENTITY_ID));
    assert_eq!(attribute(&xml, "SPNameQualifier"), Some(SP_ENTITY_ID));
    Ok(())
}

#[test]
fn idp_initiated_request_keeps_the_established_qualifiers() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let current = NameId::new("current-value")
        .with_format(NameIdFormat::Persistent)
        .with_name_qualifier("https://origin-idp.example.com")
        .with_sp_name_qualifier("https://affiliation.example.com")
        .with_sp_provided_id("sp-alias");
    let started = idp.start_name_id_management(
        &sp,
        &current,
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
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
        StartNameIdManagement::new(),
        authenticated(),
    )?;
    let request_id = attribute(&body(started.request().envelope())?, "ID")
        .ok_or("request ID is missing")?
        .to_string();
    let status = format!(
        r#"<samlp:StatusCode Value="{REQUESTER}"><samlp:StatusCode Value="{UNKNOWN_PRINCIPAL}"/></samlp:StatusCode>"#
    );

    let envelope = sp_response(&request_id, SP_ENTITY_ID, &status)?.replacen(
        "<soap:Envelope",
        r#"<soap:Envelope xmlns:xml="&#x68;ttp://www.w3.org/XML/1998/namespace""#,
        1,
    );
    let result = started.finish(&envelope);

    assert!(
        matches!(
            &result,
            Err(SamlError::StatusNotSuccess { status, .. })
                if status.top_level().as_uri() == REQUESTER && status.subordinate().map(saml_rs::SubordinateStatusCode::as_uri) == Some(UNKNOWN_PRINCIPAL)
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn a_received_relative_subordinate_status_is_not_written_into_a_response() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let started = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
        authenticated(),
    )?;
    let request_id = attribute(&body(started.request().envelope())?, "ID")
        .ok_or("request ID is missing")?
        .to_string();
    let relative = format!(
        r#"<samlp:StatusCode Value="{REQUESTER}"><samlp:StatusCode Value="relative"/></samlp:StatusCode>"#
    );
    let Err(SamlError::StatusNotSuccess { status, .. }) =
        started.finish(&sp_response(&request_id, SP_ENTITY_ID, &relative)?)
    else {
        return Err("the relative subordinate status was not reported".into());
    };
    let request = received_request(idp.receive_name_id_management(
        &sp,
        &sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?,
        authenticated(),
        validation(),
    )?)?;

    let answered = idp.respond_name_id_management(&sp, &request, &status);

    assert!(
        matches!(answered, Err(SamlError::Invalid(_))),
        "{answered:?}"
    );
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
        StartNameIdManagement::new(),
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
    let transient_default = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .name_id_format(NameIdFormat::Transient)
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_NIM_URL,
        )?))
        .build()?,
    );

    for (idp, current) in [
        (
            identity_provider(Some(IDP_NIM_URL))?,
            NameId::generate_transient(),
        ),
        (transient_default, NameId::new("current-value")),
        (
            identity_provider(Some(IDP_NIM_URL))?,
            NameId::new("current-value")
                .with_format(NameIdFormat::Custom(format!("\n {TRANSIENT}\t"))),
        ),
    ] {
        let started = idp.start_name_id_management(
            &sp,
            &current,
            &NameIdChange::Terminate,
            StartNameIdManagement::new(),
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
            NameId::new(long.clone()).with_format(NameIdFormat::Persistent),
            NameIdChange::Terminate,
        ),
        (
            NameId::new(long.clone()).with_format(NameIdFormat::Custom(format!(" {PERSISTENT} "))),
            NameIdChange::Terminate,
        ),
    ] {
        let result = idp.start_name_id_management(
            &sp,
            &current,
            &change,
            StartNameIdManagement::new(),
            authenticated(),
        );
        assert!(matches!(result, Err(SamlError::Invalid(_))));
    }
    Ok(())
}

#[test]
fn a_value_or_qualifier_of_only_xml_whitespace_is_not_sent() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let start = |current: &NameId, change: &NameIdChange| {
        idp.start_name_id_management(
            &sp,
            current,
            change,
            StartNameIdManagement::new(),
            authenticated(),
        )
    };
    let persistent = |value: &str| NameId::new(value).with_format(NameIdFormat::Persistent);

    start(
        &persistent("\u{a0}"),
        &NameIdChange::NewId("\u{2003}".into()),
    )?;
    for (current, change) in [
        (persistent(""), NameIdChange::Terminate),
        (persistent(" \n"), NameIdChange::Terminate),
        (
            persistent("alice").with_name_qualifier("\t"),
            NameIdChange::Terminate,
        ),
        (persistent("alice"), NameIdChange::NewId(" ".into())),
    ] {
        let started = start(&current, &change);
        assert!(
            matches!(started, Err(SamlError::Invalid(_))),
            "{current:?} {change:?}: {started:?}"
        );
    }
    Ok(())
}

#[test]
fn an_entity_identifier_is_sent_only_as_core_8_3_6_allows() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let partner = "https://partner.example.org/metadata";
    let entity = |value: &str| NameId::new(value).with_format(NameIdFormat::Entity);
    let start = |current: &NameId, change: &NameIdChange| {
        idp.start_name_id_management(
            &sp,
            current,
            change,
            StartNameIdManagement::new(),
            authenticated(),
        )
    };

    start(&entity(partner), &NameIdChange::Terminate)?;
    start(
        &entity(partner),
        &NameIdChange::NewId("https://partner.example.org/next".into()),
    )?;
    for (current, change) in [
        (entity("partner.example.org"), NameIdChange::Terminate),
        (
            entity(partner).with_name_qualifier(IDP_ENTITY_ID),
            NameIdChange::Terminate,
        ),
        (
            entity(partner).with_sp_name_qualifier(SP_ENTITY_ID),
            NameIdChange::Terminate,
        ),
        (
            entity(partner).with_sp_provided_id("partner-7"),
            NameIdChange::Terminate,
        ),
        (
            entity(partner),
            NameIdChange::NewId("partner.example.org".into()),
        ),
    ] {
        let started = start(&current, &change);
        assert!(
            matches!(started, Err(SamlError::Invalid(_))),
            "{current:?} {change:?}: {started:?}"
        );
    }
    Ok(())
}

#[test]
fn a_name_id_format_that_is_not_an_absolute_uri_is_not_sent() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    for format in ["", "local-format", "urn:"] {
        let current = NameId::new("current-value").with_format(NameIdFormat::Custom(format.into()));
        let result = idp.start_name_id_management(
            &sp,
            &current,
            &NameIdChange::Terminate,
            StartNameIdManagement::new(),
            authenticated(),
        );
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message.contains("absolute URI reference")),
            "{format:?}"
        );
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
        &NameId::new("current-value")
            .with_format(NameIdFormat::Persistent)
            .with_name_qualifier(IDP_ENTITY_ID)
            .with_sp_name_qualifier(SP_ENTITY_ID)
    );
    assert_eq!(message.change(), &NameIdChange::NewId("sp-alias".into()));

    let response = idp.respond_name_id_management(&sp, &request, &Status::success())?;
    let headers: Vec<(&str, &str)> = response
        .headers()
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect();
    assert!(headers.contains(&(
        "Cache-Control",
        "no-cache, no-store, must-revalidate, private"
    )));
    assert!(headers.contains(&("Pragma", "no-cache")));
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
fn a_received_name_id_format_is_read_by_its_schema_value() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!(
        r#"<saml:NameID Format="&#xA; {PERSISTENT}&#x9;" SPNameQualifier="{SP_ENTITY_ID}">current-value</saml:NameID><samlp:Terminate/>"#
    ))?;

    let request = received_request(idp.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation(),
    )?)?;

    assert_eq!(
        request.message().name_id(),
        &NameId::new("current-value")
            .with_format(NameIdFormat::Persistent)
            .with_sp_name_qualifier(SP_ENTITY_ID)
    );
    Ok(())
}

#[test]
fn sp_initiated_termination_is_received_and_answered() -> TestResult {
    let idp =
        identity_provider_with_templates(Some(IDP_NIM_URL), tag_prefixes::templates("p", "a"))?;
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
        r#"<p:StatusCode Value="{REQUESTER}"><p:StatusCode Value="{UNKNOWN_PRINCIPAL}"/></p:StatusCode>"#
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
        let NameIdManagementReceipt::Refused(refused) = received else {
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

    let NameIdManagementReceipt::Refused(refused) = received else {
        return Err("a version mismatch was not refused".into());
    };
    assert_eq!(refused.reason(), NameIdManagementRefusal::VersionMismatch);
    let xml = body(refused.response().envelope())?;
    assert!(xml.contains(&format!(
        r#"<samlp:StatusCode Value="{VERSION_MISMATCH}"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"/></samlp:StatusCode>"#
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
        StartNameIdManagement::new(),
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
        StartNameIdManagement::new(),
        authenticated(),
    );
    assert!(
        matches!(started, Err(SamlError::MissingMetadata(name)) if name == "ManageNameIDService")
    );

    let identity_role = format!(
        r#"<IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}"><ManageNameIDService Binding="{SOAP_BINDING}" Location="https://sp.example.com/idp-role/nameid"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/idp-role/sso"/></IDPSSODescriptor><SPSSODescriptor"#
    );
    let dual_role = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &service_provider(SP_ENTITY_ID, &[])?
            .metadata_xml()
            .replacen("<SPSSODescriptor", &identity_role, 1),
        MetadataTrustPolicy::Unverified,
    )?;
    let started = idp.start_name_id_management(
        &dual_role,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
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
            PartyAuthentication::Unattested,
            MessageIntegrity::Protected,
            MessageConfidentiality::Protected,
        ),
        SoapChannel::new(
            PartyAuthentication::Mutual,
            MessageIntegrity::Unattested,
            MessageConfidentiality::Protected,
        ),
    ];
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;

    for channel in weak {
        let started = idp.start_name_id_management(
            &sp,
            &NameId::persistent("current-value")?,
            &NameIdChange::Terminate,
            StartNameIdManagement::new(),
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
        format!("<saml:Issuer>\n  {SP_ENTITY_ID}\n</saml:Issuer>"),
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

    let padded = sp_request_with(
        &format!(r#"Version="2.0" Destination=" {IDP_NIM_URL}&#9;""#),
        &format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        &format!("{}<samlp:Terminate/>", current_name_id_xml()),
    )?;
    let request = received_request(idp.receive_name_id_management(
        &sp,
        &padded,
        authenticated(),
        validation(),
    )?)?;
    assert_eq!(request.message().change(), &NameIdChange::Terminate);
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

    let two_services = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_NIM_URL,
        )?))
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            "https://idp.example.com/nameid-backup",
        )?))
        .build()?,
    );
    let request = received_request(two_services.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation(),
    )?)?;
    assert_eq!(request.message().change(), &NameIdChange::Terminate);

    let addressed = two_services.receive_name_id_management(
        &sp,
        &sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?,
        authenticated(),
        validation(),
    );
    assert!(
        matches!(addressed, Err(SamlError::RecipientEndpointAmbiguous)),
        "{addressed:?}"
    );

    let unpublished = two_services.receive_name_id_management(
        &sp,
        &envelope,
        authenticated(),
        validation()
            .with_recipient_endpoint(EndpointUrl::try_new("https://idp.example.com/unpublished")?),
    );
    assert!(
        matches!(unpublished, Err(SamlError::RecipientEndpointNotPublished)),
        "{unpublished:?}"
    );
    Ok(())
}

#[test]
fn a_replayed_request_is_rejected() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;
    let mut cache = RecordingReplayCache::default();

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
        .contains_key(&format!("manage_name_id_request_id:{SP_REQUEST_ID}")));
    Ok(())
}

#[test]
fn a_bounded_request_age_rejects_an_old_request_before_replay_storage() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_704_067_200);
    let max_age = Duration::from_secs(60 * 60);

    for (now, accepted) in [(issued, true), (issued + max_age * 2, false)] {
        let mut cache = RecordingReplayCache::default();
        let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache))
            .with_replay_retention(Duration::from_secs(300))
            .with_manage_name_id_request_age(RequestAgePolicy::Bounded { max_age });
        let received = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation);
        if accepted {
            received_request(received?)?;
        } else {
            let NameIdManagementReceipt::Refused(refused) = received? else {
                return Err("an expired request was exposed for processing".into());
            };
            assert_eq!(
                refused.reason(),
                NameIdManagementRefusal::RequestAgeOutsideWindow
            );
            let xml = body(refused.response().envelope())?;
            assert_eq!(attribute(&xml, "InResponseTo"), Some(SP_REQUEST_ID));
            assert!(xml.contains(&format!(r#"<samlp:StatusCode Value="{REQUESTER}"/>"#)));
        }
        assert_eq!(cache.seen.is_empty(), !accepted);
    }
    Ok(())
}

fn assert_refused_as_malformed(received: NameIdManagementReceipt, content: &str) -> TestResult {
    let NameIdManagementReceipt::Refused(refused) = received else {
        return Err(format!("{content} was accepted").into());
    };
    assert_eq!(
        refused.reason(),
        NameIdManagementRefusal::MalformedRequest,
        "{content}"
    );
    assert!(
        matches!(refused.content_error(), Some(SamlError::ProtocolProfile(_))),
        "{content}: {:?}",
        refused.content_error()
    );
    let xml = body(refused.response().envelope())?;
    assert_eq!(
        attribute(&xml, "InResponseTo"),
        Some(SP_REQUEST_ID),
        "{content}"
    );
    assert!(
        xml.contains(&format!(
            r#"<samlp:Status><samlp:StatusCode Value="{REQUESTER}"/></samlp:Status>"#
        )),
        "{content}: {xml}"
    );
    Ok(())
}

#[test]
fn a_request_without_one_identifier_and_one_change_is_answered_with_requester() -> TestResult {
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
        format!("{name_id}<samlp:Terminate>\u{a0}</samlp:Terminate>"),
        r#"<saml:NameID><ext:Value xmlns:ext="urn:test">alias</ext:Value></saml:NameID><samlp:Terminate/>"#
            .to_string(),
        format!("{name_id}<samlp:Terminate/>{EXTENSIONS}"),
        format!("{name_id}{EXTENSIONS}<samlp:Terminate/>"),
        format!("{EXTENSIONS}{EXTENSIONS}{name_id}<samlp:Terminate/>"),
    ] {
        let received = idp.receive_name_id_management(
            &sp,
            &sp_request(&content)?,
            authenticated(),
            validation(),
        )?;
        assert_refused_as_malformed(received, &content)?;
    }

    let issuer = format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>");
    let attributes = format!(r#"Version="2.0" Destination="{IDP_NIM_URL}""#);
    let extensions_first = sp_request_with(
        &attributes,
        "",
        &format!("{EXTENSIONS}{issuer}{name_id}<samlp:Terminate/>"),
    )?;
    let received =
        idp.receive_name_id_management(&sp, &extensions_first, authenticated(), validation())?;
    assert_refused_as_malformed(received, "Extensions before Issuer")?;

    let weak = SoapChannel::new(
        PartyAuthentication::Unattested,
        MessageIntegrity::Protected,
        MessageConfidentiality::Protected,
    );
    let received = idp.receive_name_id_management(&sp, &sp_request(&name_id)?, weak, validation());
    assert!(
        matches!(received, Err(SamlError::SoapChannelProtection)),
        "{received:?}"
    );
    let from_other = sp_request_with(
        &attributes,
        &format!("<saml:Issuer>{OTHER_ENTITY_ID}</saml:Issuer>"),
        &name_id,
    )?;
    let received = idp.receive_name_id_management(&sp, &from_other, authenticated(), validation());
    assert!(
        matches!(received, Err(SamlError::IssuerMismatch { .. })),
        "{received:?}"
    );
    let misaddressed = sp_request_with(
        r#"Version="2.0" Destination="https://idp.example.com/elsewhere""#,
        &issuer,
        &name_id,
    )?;
    let received =
        idp.receive_name_id_management(&sp, &misaddressed, authenticated(), validation());
    assert!(
        matches!(received, Err(SamlError::DestinationMismatch { .. })),
        "{received:?}"
    );

    let in_order = sp_request(&format!("{EXTENSIONS}{name_id}<samlp:Terminate/>"))?;
    let request = received_request(idp.receive_name_id_management(
        &sp,
        &in_order,
        authenticated(),
        validation(),
    )?)?;
    assert_eq!(request.message().change(), &NameIdChange::Terminate);
    Ok(())
}

#[test]
#[cfg(not(crypto))]
fn a_present_signature_requires_a_crypto_provider_even_on_an_authenticated_channel() -> TestResult {
    let idp = identity_provider(Some(IDP_NIM_URL))?;
    let sp = soap_service_provider()?;
    let signature = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#;
    let envelope = sp_request(&format!(
        "{signature}{}<samlp:Terminate/>",
        current_name_id_xml()
    ))?;
    let result = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());
    assert!(
        matches!(result, Err(SamlError::Unsupported(_))),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn soap_envelopes_are_read_under_the_configured_xml_limits() -> TestResult {
    let mut xml = saml_rs::XmlPolicy::default();
    xml.limits.max_depth = 6;
    xml.limits.max_attribute_value_bytes = 64 * 1024;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .name_id_format(NameIdFormat::Persistent)
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_NIM_URL,
        )?))
        .xml(xml)
        .build()?,
    );
    let sp = soap_service_provider()?;
    let deep_header =
        "<soap:Header><a><b><c><d><e>note</e></d></c></b></a></soap:Header><soap:Body>";
    let consent = format!(r#"Consent="{}" "#, "a".repeat(20 * 1024));

    let request = sp_request(&format!("{}<samlp:Terminate/>", current_name_id_xml()))?;
    let refused = idp.receive_name_id_management(
        &sp,
        &request.replacen("<soap:Body>", deep_header, 1),
        authenticated(),
        validation(),
    );
    assert!(
        matches!(
            &refused,
            Err(SamlError::SoapEnvelope {
                fault: saml_rs::SoapFaultCode::Client,
                source,
                ..
            }) if matches!(
                source.downcast_ref::<SamlError>(),
                Some(SamlError::LimitExceeded {
                    limit: saml_rs::ResourceLimit::XmlDepth,
                    ..
                })
            )
        ),
        "{refused:?}"
    );
    received_request(idp.receive_name_id_management(
        &sp,
        &request,
        authenticated(),
        validation(),
    )?)?;
    received_request(idp.receive_name_id_management(
        &sp,
        &request.replacen(
            "<samlp:ManageNameIDRequest ",
            &format!("<samlp:ManageNameIDRequest {consent}"),
            1,
        ),
        authenticated(),
        validation(),
    )?)?;

    let started = idp.start_name_id_management(
        &sp,
        &NameId::new("current-value"),
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
        authenticated(),
    )?;
    let xml = body(started.request().envelope())?;
    let request_id = attribute(&xml, "ID").ok_or("request ID is missing")?;
    let response = sp_response(request_id, SP_ENTITY_ID, &success_status())?;
    let refused = started.finish(&response.replacen("<soap:Body>", deep_header, 1));
    assert!(
        matches!(
            &refused,
            Err(SamlError::SoapEnvelope {
                fault: saml_rs::SoapFaultCode::Client,
                source,
                ..
            }) if matches!(
                source.downcast_ref::<SamlError>(),
                Some(SamlError::LimitExceeded {
                    limit: saml_rs::ResourceLimit::XmlDepth,
                    ..
                })
            )
        ),
        "{refused:?}"
    );
    started.finish(&response)?;
    started.finish(&response.replacen(
        "<samlp:ManageNameIDResponse ",
        &format!("<samlp:ManageNameIDResponse {consent}"),
        1,
    ))?;
    Ok(())
}
