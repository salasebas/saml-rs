//! LogoutRequest NameID qualifiers, respond_slo issuer, and SLO endpoint locations.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::xml::dom::parse;
use saml_rs::{
    BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, LogoutRequest, LogoutSigning, LogoutSubject, MetadataTrustPolicy, NameId,
    NameIdFormat, Outbound, PrivateKeyPem, ReplayPolicy, RespondSlo, Saml, SamlError,
    SamlValidationContext, SessionIndex, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, StartSlo,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const OTHER_SP_ENTITY_ID: &str = "https://other.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SLO: &str = "https://sp.example.com/slo/post";
const SP_SLO_RESPONSE: &str = "https://sp.example.com/slo/response";
const IDP_SSO: &str = "https://idp.example.com/sso/post";
const IDP_SLO: &str = "https://idp.example.com/slo/post";
const IDP_SLO_SECOND: &str = "https://idp.example.com/slo/second";
const IDP_SLO_REQUEST: &str = "https://idp.example.com/slo/request";
const IDP_SLO_RESPONSE: &str = "https://idp.example.com/slo/response";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn qualified_subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        NameId::with_qualifiers(
            "alice",
            Some(NameIdFormat::Persistent),
            Some("idp\"&qual".to_string()),
            Some("sp&qual".to_string()),
            Some("prov\"ided".to_string()),
        ),
        SessionIndex::try_new("_session")?,
    ))
}

fn sp(validation_policy: SpValidationPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(saml_rs::AcsEndpoint::post(SP_ACS)?)
            .slo_endpoint(SloEndpoint::post(SP_SLO)?)
            .credentials(credentials())
            .validation(validation_policy)
            .build()?,
    )
}

fn idp(
    validation_policy: IdpValidationPolicy,
    name_id_format: Option<NameIdFormat>,
    slo_urls: &[&str],
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO)?);
    for url in slo_urls {
        builder = builder.slo_endpoint(SloEndpoint::post(*url)?);
    }
    if let Some(format) = name_id_format {
        builder = builder.name_id_format(format);
    }
    Saml::idp(
        builder
            .credentials(credentials())
            .validation(validation_policy)
            .build()?,
    )
}

fn descriptor_pair(
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

fn post_xml<Message>(outbound: &Outbound<Message>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(base64_decode(
        &outbound.raw_context().context,
    )?)?)
}

struct RenderedNameId {
    value: String,
    format: Option<String>,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
    sp_provided_id: Option<String>,
}

fn rendered_name_id(xml: &str) -> Result<RenderedNameId, Box<dyn std::error::Error>> {
    let document = parse(xml)?;
    let name_id = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "NameID")
        .ok_or("missing NameID")?;
    Ok(RenderedNameId {
        value: name_id.text.clone(),
        format: name_id.attr("Format").map(str::to_string),
        name_qualifier: name_id.attr("NameQualifier").map(str::to_string),
        sp_name_qualifier: name_id.attr("SPNameQualifier").map(str::to_string),
        sp_provided_id: name_id.attr("SPProvidedID").map(str::to_string),
    })
}

fn assert_qualified(
    name_id: &NameId,
    rendered: &RenderedNameId,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(name_id.value(), "alice");
    assert_eq!(name_id.format(), Some(&NameIdFormat::Persistent));
    assert_eq!(name_id.name_qualifier(), Some("idp\"&qual"));
    assert_eq!(name_id.sp_name_qualifier(), Some("sp&qual"));
    assert_eq!(name_id.sp_provided_id(), Some("prov\"ided"));
    assert_eq!(rendered.value, "alice");
    assert_eq!(rendered.format.as_deref(), Some(PERSISTENT));
    assert_eq!(rendered.name_qualifier.as_deref(), Some("idp\"&qual"));
    assert_eq!(rendered.sp_name_qualifier.as_deref(), Some("sp&qual"));
    assert_eq!(rendered.sp_provided_id.as_deref(), Some("prov\"ided"));
    Ok(())
}

#[test]
fn start_slo_keeps_nameid_format_and_qualifiers() -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::recommended())?;
    let identity_provider = idp(
        IdpValidationPolicy::recommended(),
        Some(NameIdFormat::EmailAddress),
        &[IDP_SLO],
    )?;
    let (sp_descriptor, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let subject = qualified_subject()?;

    let from_sp = service_provider.start_slo(&idp_descriptor, subject.clone(), StartSlo::post())?;
    let sp_rendered = rendered_name_id(&post_xml(&from_sp.outbound)?)?;
    let received_by_idp = identity_provider.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(from_sp.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_qualified(
        received_by_idp
            .message()
            .name_id()
            .ok_or("missing received NameID")?,
        &sp_rendered,
    )?;

    let from_idp = identity_provider.start_slo(&sp_descriptor, subject, StartSlo::post())?;
    let idp_rendered = rendered_name_id(&post_xml(&from_idp.outbound)?)?;
    let received_by_sp = service_provider.receive_slo(
        &idp_descriptor,
        BrowserInput::<LogoutRequest>::post(from_idp.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_qualified(
        received_by_sp
            .message()
            .name_id()
            .ok_or("missing received NameID")?,
        &idp_rendered,
    )?;
    Ok(())
}

#[test]
fn start_slo_uses_subject_format_before_the_configured_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::recommended())?;
    let identity_provider = idp(
        IdpValidationPolicy::recommended(),
        Some(NameIdFormat::EmailAddress),
        &[IDP_SLO],
    )?;
    let (sp_descriptor, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;

    let persistent = identity_provider.start_slo(
        &sp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice", Some(NameIdFormat::Persistent)),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post(),
    )?;
    let persistent_xml = rendered_name_id(&post_xml(&persistent.outbound)?)?;
    assert_eq!(persistent_xml.format.as_deref(), Some(PERSISTENT));

    let fallback = identity_provider.start_slo(
        &sp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post(),
    )?;
    let fallback_xml = rendered_name_id(&post_xml(&fallback.outbound)?)?;
    assert_eq!(fallback_xml.format.as_deref(), Some(EMAIL));
    let received = service_provider.receive_slo(
        &idp_descriptor,
        BrowserInput::<LogoutRequest>::post(fallback.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(
        received.message().name_id().and_then(NameId::format),
        Some(&NameIdFormat::EmailAddress)
    );
    Ok(())
}

#[test]
fn respond_slo_rejects_a_logout_request_issuer_from_another_party(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::recommended())?;
    let identity_provider = idp(IdpValidationPolicy::recommended(), None, &[IDP_SLO])?;
    let (sp_descriptor, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let other = SpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{OTHER_SP_ENTITY_ID}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/slo"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    match identity_provider.respond_slo(&other, &received, RespondSlo::post()) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, SP_ENTITY_ID);
            assert_eq!(actual.as_deref(), Some(OTHER_SP_ENTITY_ID));
        }
        other => return Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn logout_response_uses_response_location_and_request_uses_location(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::compatibility())?;
    let identity_provider = idp(IdpValidationPolicy::compatibility(), None, &[IDP_SLO])?;
    let idp_for_requests = IdpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO}"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SLO_REQUEST}" ResponseLocation="{IDP_SLO_RESPONSE}"/></IDPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = service_provider.start_slo(
        &idp_for_requests,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    assert_eq!(
        started.outbound.post_form()?.action().as_str(),
        IDP_SLO_REQUEST
    );

    let sp_for_responses = SpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SP_SLO}" ResponseLocation="{SP_SLO_RESPONSE}"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SP_ACS}" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let local_idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        identity_provider.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let request = service_provider.start_slo(
        &local_idp,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    let received = identity_provider.receive_slo(
        &sp_for_responses,
        BrowserInput::<LogoutRequest>::post(request.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response =
        identity_provider.respond_slo(&sp_for_responses, &received, RespondSlo::post())?;
    assert_eq!(response.post_form()?.action().as_str(), SP_SLO_RESPONSE);
    Ok(())
}

#[test]
fn second_published_slo_location_is_an_accepted_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::compatibility())?;
    let identity_provider = idp(
        IdpValidationPolicy::compatibility(),
        None,
        &[IDP_SLO, IDP_SLO_SECOND],
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        service_provider.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let logout_request = |destination: &str| {
        format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer><saml:NameID>alice@example.com</saml:NameID></samlp:LogoutRequest>"#
        )
    };
    let input = |xml: &str| {
        BrowserInput::<LogoutRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(xml.as_bytes()),
        )])
    };

    let accepted = identity_provider.receive_slo(
        &sp_descriptor,
        input(&logout_request(IDP_SLO_SECOND)),
        validation(),
    )?;
    assert_eq!(
        accepted.message().destination().map(|url| url.as_str()),
        Some(IDP_SLO_SECOND)
    );

    let rejected = identity_provider.receive_slo(
        &sp_descriptor,
        input(&logout_request("https://idp.example.com/slo/unknown")),
        validation(),
    );
    match rejected {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_SLO);
            assert_eq!(
                actual.as_deref(),
                Some("https://idp.example.com/slo/unknown")
            );
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
    Ok(())
}
