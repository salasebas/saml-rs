//! Metadata `validUntil` and `cacheDuration`.
//!
//! SAML Metadata §§2.3.1-2.3.2 and Approved Errata 05 E76 and E94.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::{Duration, SystemTime};

use saml_rs::error::TimeWindowField;
use saml_rs::raw::Binding;
use saml_rs::xml::dom::parse;
use saml_rs::{
    AcsEndpoint, ArtifactDereference, ArtifactResolutionService, ArtifactUses, AuthnRequest,
    BrowserInput, EndpointUrl, EntityId, FormField, IdentifierEncryptionPolicy, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, IssuedArtifacts, IssuedMessage, ManageNameIdService,
    MetadataLifetime, MetadataTrustPolicy, NameId, NameIdChange, NameIdFormat, PaosClientRequest,
    ReceivedNameIdManagement, ReplayPolicy, Saml, SamlError, SamlValidationContext, SoapChannel,
    SoapProtocolMessage, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartPaosSso,
    StartSso, Status,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const IDP_NIM_URL: &str = "https://idp.example.com/nameid";
const SOAP_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const Y2001: u64 = 978_307_200;

fn at(unix_seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
}

fn whole_seconds_from_now(seconds: u64) -> Result<SystemTime, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    Ok(at(now.as_secs() + seconds))
}

fn sp(lifetime: Option<MetadataLifetime>) -> Result<Saml<saml_rs::Sp>, SamlError> {
    let builder = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?.mark_default())
        .validation(SpValidationPolicy::compatibility());
    let builder = match lifetime {
        Some(lifetime) => builder.metadata_lifetime(lifetime),
        None => builder,
    };
    Saml::sp(builder.build()?)
}

fn idp(lifetime: Option<MetadataLifetime>) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_NIM_URL,
        )?))
        .name_id_format(NameIdFormat::Persistent)
        .validation(IdpValidationPolicy::compatibility());
    let builder = match lifetime {
        Some(lifetime) => builder.metadata_lifetime(lifetime),
        None => builder,
    };
    Saml::idp(builder.build()?)
}

fn idp_descriptor(idp: &Saml<saml_rs::Idp>) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn sp_descriptor(sp: &Saml<saml_rs::Sp>) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

/// `sp` metadata that also publishes a SOAP `ManageNameIDService`, which
/// `SpConfig` does not build.
fn soap_name_id_sp_descriptor(sp: &Saml<saml_rs::Sp>) -> Result<SpDescriptor, SamlError> {
    let metadata = sp.metadata_xml().replacen(
        "<AssertionConsumerService",
        &format!(
            r#"<ManageNameIDService Binding="{SOAP_BINDING}" Location="https://sp.example.com/nameid"/><AssertionConsumerService"#
        ),
        1,
    );
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

/// A SOAP `ManageNameIDRequest` from the service provider to terminate its
/// persistent identifier.
fn sp_terminate_request() -> Result<String, SamlError> {
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_sp_manage_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="{IDP_NIM_URL}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer><saml:NameID Format="{PERSISTENT}" NameQualifier="{IDP_ENTITY_ID}" SPNameQualifier="{SP_ENTITY_ID}">current-value</saml:NameID><samlp:Terminate/></samlp:ManageNameIDRequest>"#
    );
    Ok(
        SoapProtocolMessage::request(EndpointUrl::try_new(IDP_NIM_URL)?, &xml)?
            .envelope()
            .to_string(),
    )
}

fn artifact_message() -> Result<IssuedMessage, SamlError> {
    IssuedMessage::protocol(format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
    ))
}

fn is_valid_until_error<T>(result: &Result<T, SamlError>) -> bool {
    matches!(
        result,
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    )
}

/// The AuthnRequest that `sp` sends to `idp`, posted to the identity provider.
fn posted_authn_request(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<BrowserInput<AuthnRequest>, Box<dyn std::error::Error>> {
    let started = sp.start_sso(&idp_descriptor(idp)?, StartSso::post())?;
    let context = started.outbound.raw_context();
    if context.binding != Binding::Post {
        return Err("expected an HTTP-POST AuthnRequest".into());
    }
    Ok(BrowserInput::<AuthnRequest>::post(vec![FormField::new(
        "SAMLRequest",
        context.context.clone(),
    )]))
}

#[test]
fn start_sso_refuses_identity_provider_metadata_after_valid_until(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(None)?;
    let expired = idp_descriptor(&idp(Some(MetadataLifetime::ValidUntil(at(Y2001))))?)?;
    let an_hour_from_now = whole_seconds_from_now(3600)?;
    let current = idp_descriptor(&idp(Some(MetadataLifetime::ValidUntil(an_hour_from_now)))?)?;

    assert!(is_valid_until_error(
        &sp.start_sso(&expired, StartSso::post())
    ));
    sp.start_sso(&current, StartSso::post())?;
    Ok(())
}

#[test]
fn receive_sso_compares_valid_until_with_the_context_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid_until = whole_seconds_from_now(3600)?;
    let sp = sp(Some(MetadataLifetime::ValidUntil(valid_until)))?;
    let idp = idp(None)?;
    let descriptor = sp_descriptor(&sp)?;
    let context = |now| SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility);

    idp.receive_sso(
        &descriptor,
        posted_authn_request(&sp, &idp)?,
        context(valid_until - Duration::from_secs(1)),
    )?;
    let at_valid_until = idp.receive_sso(
        &descriptor,
        posted_authn_request(&sp, &idp)?,
        context(valid_until),
    );

    assert!(is_valid_until_error(&at_valid_until));
    Ok(())
}

#[test]
fn soap_artifact_name_id_and_paos_flows_refuse_expired_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let expired = Some(MetadataLifetime::ValidUntil(at(Y2001)));
    let expired_sp = soap_name_id_sp_descriptor(&sp(expired)?)?;
    let expired_idp = idp_descriptor(&idp(expired)?)?;
    let sp = sp(None)?;
    let idp = idp(None)?;
    let current_sp = soap_name_id_sp_descriptor(&sp)?;
    let current_idp = idp_descriptor(&idp)?;
    let channel = SoapChannel::mutually_authenticated_confidential();
    let now =
        || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);
    let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60));
    let artifact = idp.issue_artifact(&current_sp, artifact_message()?, 0, &mut issued)?;
    let resolve_envelope = sp
        .resolve_artifact(
            &current_idp,
            &artifact,
            ArtifactDereference::web_browser_sso(channel)?,
            &mut ArtifactUses::enforce_single_use(Duration::from_secs(600)),
        )?
        .request()
        .envelope()
        .to_string();
    let ReceivedNameIdManagement::Request(name_id_request) =
        idp.receive_name_id_management(&current_sp, &sp_terminate_request()?, channel, now())?
    else {
        return Err("the name identifier management request was refused".into());
    };

    let results = [
        (
            "issue_artifact",
            idp.issue_artifact(&expired_sp, artifact_message()?, 0, &mut issued)
                .map(drop),
        ),
        (
            "answer_artifact_resolve",
            idp.answer_artifact_resolve(&expired_sp, &resolve_envelope, &mut issued, channel)
                .map(drop),
        ),
        (
            "resolve_artifact",
            sp.resolve_artifact(
                &expired_idp,
                &artifact,
                ArtifactDereference::web_browser_sso(channel)?,
                &mut ArtifactUses::enforce_single_use(Duration::from_secs(600)),
            )
            .map(drop),
        ),
        (
            "start_name_id_management",
            idp.start_name_id_management(
                &expired_sp,
                &NameId::new("current-value", None),
                &NameIdChange::Terminate,
                IdentifierEncryptionPolicy::PlaintextIdentifiers,
                channel,
            )
            .map(drop),
        ),
        (
            "receive_name_id_management",
            idp.receive_name_id_management(&expired_sp, &sp_terminate_request()?, channel, now())
                .map(drop),
        ),
        (
            "respond_name_id_management",
            idp.respond_name_id_management(&expired_sp, &name_id_request, &Status::success())
                .map(drop),
        ),
        (
            "start_paos_sso",
            sp.start_paos_sso(
                &expired_idp,
                PaosClientRequest::headers_checked_by_caller(),
                StartPaosSso::to_soap_endpoint("https://idp.example.com/soap")?
                    .allow_unsigned_authn_request(),
            )
            .map(drop),
        ),
    ];

    for (flow, result) in results {
        assert!(is_valid_until_error(&result), "{flow}: {result:?}");
    }
    Ok(())
}

#[test]
fn an_elapsed_cache_duration_leaves_metadata_usable() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(Some(MetadataLifetime::CacheDuration(Duration::from_secs(
        1,
    ))))?;
    let idp = idp(None)?;
    let a_day_later = SystemTime::now() + Duration::from_secs(86_400);

    idp.receive_sso(
        &sp_descriptor(&sp)?,
        posted_authn_request(&sp, &idp)?,
        SamlValidationContext::new(a_day_later, ReplayPolicy::DisabledForCompatibility),
    )?;
    Ok(())
}

#[test]
fn import_rejects_a_malformed_valid_until() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}" validUntil="2001-01-01T00:00:00"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
    );

    let imported =
        IdpDescriptor::from_metadata_xml(&xml, MetadataTrustPolicy::UnsignedForCompatibility);

    assert!(is_valid_until_error(&imported));
    Ok(())
}

#[test]
fn generated_root_carries_the_configured_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let lifetimes = [
        (None, None, None),
        (
            Some(MetadataLifetime::ValidUntil(at(Y2001))),
            Some("2001-01-01T00:00:00Z"),
            None,
        ),
        (
            Some(MetadataLifetime::CacheDuration(Duration::from_secs(86_400))),
            None,
            Some("PT86400S"),
        ),
        (
            Some(MetadataLifetime::ValidUntilAndCacheDuration {
                valid_until: at(Y2001) + Duration::from_millis(900),
                cache_duration: Duration::from_millis(1500),
            }),
            Some("2001-01-01T00:00:00Z"),
            Some("PT1.500000000S"),
        ),
    ];

    for (lifetime, valid_until, cache_duration) in lifetimes {
        let sp = sp(lifetime)?;
        let idp = idp(lifetime)?;
        for xml in [sp.metadata_xml(), idp.metadata_xml()] {
            let root = parse(xml)?.root;
            assert_eq!(root.local_name, "EntityDescriptor");
            assert_eq!(root.attr("validUntil"), valid_until, "{xml}");
            assert_eq!(root.attr("cacheDuration"), cache_duration, "{xml}");
        }
    }
    Ok(())
}
