//! Compatibility is the legacy permissive preset.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use saml_rs::binding::{
    append_signature, base64_decode, base64_encode, build_redirect_octet, deflate_raw_decode,
    deflate_raw_encode,
};
use saml_rs::constants::{signature_algorithm::RSA_SHA256, ParserType};
use saml_rs::crypto::{
    construct_message_signature, construct_saml_signature, keys::load_private_key,
};
use saml_rs::error::{SignatureVerificationReason, TimeWindowField};
use saml_rs::raw::{Binding, FlowResult};
use saml_rs::util::Value;
use saml_rs::xml::dom::parse;
use saml_rs::xml::extract;
use saml_rs::xml::fields::login_response_fields;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, BrowserInput, CertificatePem, ClockSkew, Credentials, EntityId,
    FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutBinding, LogoutCompleted,
    LogoutPolicy, LogoutRequest, LogoutResponse, LogoutSignaturePolicy, LogoutSigning,
    LogoutSubject, MetadataTrustPolicy, NameId, NameIdFormat, Outbound, PendingLogoutRequest,
    PendingSnapshot, PrivateKeyPem, Received, RelayStateParam, ReplayCache, ReplayKey,
    ReplayPolicy, RespondSlo, RespondSso, Saml, SamlError, SamlValidationContext, SessionIndex,
    SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoSession, StartSlo,
    Status, Subject, SubordinateStatusCode, TemplatePolicy,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_SLO_POST: &str = "https://sp.example.com/slo/post";
const SP_SLO_REDIRECT: &str = "https://sp.example.com/slo/redirect";
const SP_SLO_SIMPLESIGN: &str = "https://sp.example.com/slo/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SLO_POST: &str = "https://idp.example.com/slo/post";
const IDP_SLO_REDIRECT: &str = "https://idp.example.com/slo/redirect";
const IDP_SLO_SIMPLESIGN: &str = "https://idp.example.com/slo/simple-sign";

const ALL_LOGOUT_BINDINGS: [LogoutBinding; 3] = [
    LogoutBinding::Post,
    LogoutBinding::Redirect,
    LogoutBinding::SimpleSign,
];
const UNSIGNED_COMPATIBILITY_BINDINGS: [LogoutBinding; 2] =
    [LogoutBinding::Post, LogoutBinding::Redirect];

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

#[derive(Debug, Clone, Copy)]
enum LocalSloRole {
    Sp,
    Idp,
}

const LOCAL_SLO_ROLES: [LocalSloRole; 2] = [LocalSloRole::Sp, LocalSloRole::Idp];

struct SloEndpointSet {
    post: &'static str,
    redirect: &'static str,
    simple_sign: &'static str,
}

impl SloEndpointSet {
    fn for_binding(&self, binding: LogoutBinding) -> &'static str {
        match binding {
            LogoutBinding::Post => self.post,
            LogoutBinding::Redirect => self.redirect,
            LogoutBinding::SimpleSign => self.simple_sign,
        }
    }
}

impl LocalSloRole {
    fn endpoint(self, binding: LogoutBinding) -> &'static str {
        let endpoints = match self {
            Self::Sp => SloEndpointSet {
                post: SP_SLO_POST,
                redirect: SP_SLO_REDIRECT,
                simple_sign: SP_SLO_SIMPLESIGN,
            },
            Self::Idp => SloEndpointSet {
                post: IDP_SLO_POST,
                redirect: IDP_SLO_REDIRECT,
                simple_sign: IDP_SLO_SIMPLESIGN,
            },
        };
        endpoints.for_binding(binding)
    }
}

const BAD_LOGOUT_RESPONSE_TEMPLATE: &str = r#"
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}"
    Destination="{Destination}" InResponseTo="_wrong">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
</samlp:LogoutResponse>
"#;

const CUSTOM_LOGOUT_REQUEST_TEMPLATE: &str = r#"
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="__ISSUE_INSTANT__"__NOT_ON_OR_AFTER__
    Destination="{Destination}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
    <samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>
"#;

const SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE: &str = r#"
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}"
    NotOnOrAfter="{NotOnOrAfter}" Destination="{Destination}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
    <samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>
"#;

fn logout_request_template(issue_instant: &str, not_on_or_after: Option<&str>) -> String {
    let not_on_or_after = not_on_or_after
        .map(|value| format!(r#" NotOnOrAfter="{value}""#))
        .unwrap_or_default();
    CUSTOM_LOGOUT_REQUEST_TEMPLATE
        .replace("__ISSUE_INSTANT__", issue_instant)
        .replace("__NOT_ON_OR_AFTER__", &not_on_or_after)
}

fn signing_sp_validation() -> SpValidationPolicy {
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        authn_requests: AuthnRequestSigningPolicy::Sign,
        audience: AudienceValidationPolicy::Validate,
        ..SpValidationPolicy::recommended()
    }
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    IdpValidationPolicy {
        authn_requests: AuthnRequestValidationPolicy::RequireSigned,
        ..IdpValidationPolicy::recommended()
    }
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

#[derive(Default)]
struct MemoryReplayCache {
    seen: HashMap<String, SystemTime>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

struct ExpiringReplayCache {
    now: SystemTime,
    seen: HashMap<String, SystemTime>,
}

impl ExpiringReplayCache {
    fn new(now: SystemTime) -> Self {
        Self {
            now,
            seen: HashMap::new(),
        }
    }
}

impl ReplayCache for ExpiringReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        self.seen.retain(|_, deadline| self.now < *deadline);
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(signing_sp_validation(), None)
}

fn sp_config_with_validation(validation: SpValidationPolicy) -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(validation, None)
}

fn sp_config_with_validation_and_logout_request_template(
    validation: SpValidationPolicy,
    template: Option<&str>,
) -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
        .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(SP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(SP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(validation)
        .templates(TemplatePolicy {
            logout_request_template: template.map(str::to_string),
            ..TemplatePolicy::default()
        })
        .build()
}

fn sp_config_with_logout_request_template(template: &str) -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(signing_sp_validation(), Some(template))
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_validation(signed_authn_request_idp_validation())
}

fn idp_config_with_validation(validation: IdpValidationPolicy) -> Result<IdpConfig, SamlError> {
    idp_config_with_validation_and_logout_request_template(validation, None)
}

fn idp_config_with_validation_and_logout_request_template(
    validation: IdpValidationPolicy,
    template: Option<&str>,
) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(IDP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(validation)
        .templates(TemplatePolicy {
            logout_request_template: template.map(str::to_string),
            ..TemplatePolicy::default()
        })
        .build()
}

fn idp_config_with_issuance(
    lifetime: Duration,
    logout_request_template: Option<String>,
    credentials: Credentials,
    validation: IdpValidationPolicy,
) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(IDP_SLO_SIMPLESIGN)?)
        .credentials(credentials)
        .issuance_lifetime(lifetime)
        .validation(validation)
        .templates(TemplatePolicy {
            logout_request_template,
            ..TemplatePolicy::default()
        })
        .build()
}

fn idp_config_with_logout_response_template(
    logout_response_template: String,
) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .credentials(credentials())
        .validation(signed_authn_request_idp_validation())
        .templates(TemplatePolicy {
            logout_response_template: Some(logout_response_template),
            ..TemplatePolicy::default()
        })
        .build()
}

fn bad_template_idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_logout_response_template(BAD_LOGOUT_RESPONSE_TEMPLATE.to_string())
}

fn bad_profile_template_idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_logout_response_template(BAD_LOGOUT_RESPONSE_TEMPLATE.replace(
        r#"IssueInstant="{IssueInstant}""#,
        r#"IssueInstant="not-a-date""#,
    ))
}

fn facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    Ok((Saml::sp(sp_config()?)?, Saml::idp(idp_config()?)?))
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
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
    Ok((sp_descriptor, idp_descriptor))
}

fn subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        NameId::new("alice@example.com", None),
        SessionIndex::try_new("_session123")?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(
        SystemTime::now(),
        saml_rs::ReplayPolicy::DisabledForCompatibility,
    )
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(Duration::from_secs(5 * 60))
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn logout_request_input(
    outbound: &Outbound<LogoutRequest>,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutRequest>, SamlError> {
    match binding {
        LogoutBinding::Redirect => {
            let url = outbound.redirect_url()?;
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutRequest>::redirect(query))
        }
        LogoutBinding::Post => Ok(BrowserInput::<LogoutRequest>::post(post_fields(outbound)?)),
        LogoutBinding::SimpleSign => Ok(BrowserInput::<LogoutRequest>::simple_sign(post_fields(
            outbound,
        )?)),
    }
}

fn tampered_logout_request_expiration_input(
    outbound: &Outbound<LogoutRequest>,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutRequest>, Box<dyn std::error::Error>> {
    let xml = outbound_xml(outbound, "SAMLRequest")?;
    let expiration = parse(&xml)?
        .root
        .attr("NotOnOrAfter")
        .ok_or("missing LogoutRequest NotOnOrAfter")?
        .to_string();
    let replacement = "2099-01-01T00:00:00Z";
    let tampered = xml.replacen(
        &format!("NotOnOrAfter=\"{expiration}\""),
        &format!("NotOnOrAfter=\"{replacement}\""),
        1,
    );
    if tampered == xml {
        return Err("failed to tamper LogoutRequest expiration".into());
    }

    match binding {
        LogoutBinding::Redirect => {
            let url = outbound.redirect_url()?;
            let (_, query) = url
                .split_once('?')
                .ok_or("redirect URL is missing a query")?;
            let encoded = base64_encode(&deflate_raw_encode(tampered.as_bytes())?);
            let encoded_pair = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("SAMLRequest", &encoded)
                .finish();
            let replacement = encoded_pair
                .strip_prefix("SAMLRequest=")
                .ok_or("failed to encode SAMLRequest")?;
            let mut replaced = false;
            let query = query
                .split('&')
                .map(|part| {
                    if part.starts_with("SAMLRequest=") {
                        replaced = true;
                        format!("SAMLRequest={replacement}")
                    } else {
                        part.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
            if !replaced {
                return Err("redirect URL is missing SAMLRequest".into());
            }
            Ok(BrowserInput::<LogoutRequest>::redirect(query))
        }
        LogoutBinding::Post | LogoutBinding::SimpleSign => {
            let fields = post_fields(outbound)?
                .into_iter()
                .map(|field| {
                    if field.name() == "SAMLRequest" {
                        FormField::new("SAMLRequest", base64_encode(tampered.as_bytes()))
                    } else {
                        field
                    }
                })
                .collect();
            match binding {
                LogoutBinding::Post => Ok(BrowserInput::<LogoutRequest>::post(fields)),
                LogoutBinding::SimpleSign => Ok(BrowserInput::<LogoutRequest>::simple_sign(fields)),
                LogoutBinding::Redirect => Err("unreachable binding".into()),
            }
        }
    }
}

fn start_slo_for_binding(binding: LogoutBinding) -> StartSlo {
    match binding {
        LogoutBinding::Redirect => StartSlo::redirect(),
        LogoutBinding::Post => StartSlo::post(),
        LogoutBinding::SimpleSign => StartSlo::simple_sign(),
    }
}

fn start_unsigned_slo_for_binding(binding: LogoutBinding) -> StartSlo {
    start_slo_for_binding(binding).signing(LogoutSigning::DoNotSignForCompatibility)
}

#[derive(Debug, Clone, Copy)]
enum RequestProtection {
    Signed,
    UnsignedCompatibility,
}

fn receive_custom_logout_request(
    template: &str,
    binding: LogoutBinding,
    receiver_role: LocalSloRole,
    protection: RequestProtection,
    validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let start_options = match protection {
        RequestProtection::Signed => start_slo_for_binding(binding),
        RequestProtection::UnsignedCompatibility => start_unsigned_slo_for_binding(binding),
    };
    match receiver_role {
        LocalSloRole::Idp => {
            let sp = Saml::sp(sp_config_with_logout_request_template(template)?)?;
            let idp = Saml::idp(match protection {
                RequestProtection::Signed => idp_config()?,
                RequestProtection::UnsignedCompatibility => {
                    idp_config_with_validation(IdpValidationPolicy::compatibility())?
                }
            })?;
            let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
            let started = sp.start_slo(&idp_descriptor, subject()?, start_options)?;
            idp.receive_slo(
                &sp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation,
            )
        }
        LocalSloRole::Sp => {
            let sp = Saml::sp(match protection {
                RequestProtection::Signed => sp_config()?,
                RequestProtection::UnsignedCompatibility => {
                    sp_config_with_validation(SpValidationPolicy::compatibility())?
                }
            })?;
            let idp = Saml::idp(idp_config_with_validation_and_logout_request_template(
                signed_authn_request_idp_validation(),
                Some(template),
            )?)?;
            let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
            let started = idp.start_slo(&sp_descriptor, subject()?, start_options)?;
            sp.receive_slo(
                &idp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation,
            )
        }
    }
}

fn sender_entity_id(receiver_role: LocalSloRole) -> &'static str {
    match receiver_role {
        LocalSloRole::Idp => SP_ENTITY_ID,
        LocalSloRole::Sp => IDP_ENTITY_ID,
    }
}

fn logout_request_xml(id: &str, issuer: &str, destination: Option<&str>) -> String {
    let destination = destination
        .map(|destination| format!(r#" Destination="{destination}""#))
        .unwrap_or_default();
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{id}" Version="2.0" IssueInstant="2000-01-01T00:00:00Z"{destination}>
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:NameID>alice@example.com</saml:NameID>
    <samlp:SessionIndex>_session123</samlp:SessionIndex>
</samlp:LogoutRequest>"#
    )
}

fn signed_logout_request_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutRequest>, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    match binding {
        LogoutBinding::Post => {
            let signed = construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], None)?;
            Ok(BrowserInput::<LogoutRequest>::post(vec![FormField::new(
                "SAMLRequest",
                base64_encode(signed.as_bytes()),
            )]))
        }
        LogoutBinding::Redirect => {
            let octet = build_redirect_octet(ParserType::LogoutRequest, xml, None, RSA_SHA256)?;
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            let url = append_signature("https://receiver.example.com/slo", &octet, &signature);
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutRequest>::redirect(query))
        }
        LogoutBinding::SimpleSign => {
            let octet = format!("SAMLRequest={xml}&SigAlg={RSA_SHA256}");
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            Ok(BrowserInput::<LogoutRequest>::simple_sign(vec![
                FormField::new("SAMLRequest", base64_encode(xml.as_bytes())),
                FormField::new("SigAlg", RSA_SHA256),
                FormField::new("Signature", signature),
            ]))
        }
    }
}

fn unsigned_logout_request_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutRequest>, SamlError> {
    match binding {
        LogoutBinding::Post => Ok(BrowserInput::<LogoutRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(xml.as_bytes()),
        )])),
        LogoutBinding::Redirect => {
            let url = saml_rs::binding::build_redirect_url(
                "https://receiver.example.com/slo",
                ParserType::LogoutRequest,
                xml,
                None,
            )?;
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutRequest>::redirect(query))
        }
        LogoutBinding::SimpleSign => Err(SamlError::Invalid(
            "SimpleSign input requires its binding-level signature".into(),
        )),
    }
}

fn receive_crafted_logout_request(
    xml: &str,
    binding: LogoutBinding,
    receiver_role: LocalSloRole,
    protection: RequestProtection,
    validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let sp = Saml::sp(match (receiver_role, protection) {
        (LocalSloRole::Sp, RequestProtection::UnsignedCompatibility) => {
            sp_config_with_validation(SpValidationPolicy::compatibility())?
        }
        _ => sp_config()?,
    })?;
    let idp = Saml::idp(match (receiver_role, protection) {
        (LocalSloRole::Idp, RequestProtection::UnsignedCompatibility) => {
            idp_config_with_validation(IdpValidationPolicy::compatibility())?
        }
        _ => idp_config()?,
    })?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let input = match protection {
        RequestProtection::Signed => signed_logout_request_input(xml, binding)?,
        RequestProtection::UnsignedCompatibility => unsigned_logout_request_input(xml, binding)?,
    };
    match receiver_role {
        LocalSloRole::Idp => idp.receive_slo(&sp_descriptor, input, validation),
        LocalSloRole::Sp => sp.receive_slo(&idp_descriptor, input, validation),
    }
}

fn logout_response_xml(
    id: &str,
    issuer: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> String {
    let destination = destination
        .map(|destination| format!(r#" Destination="{destination}""#))
        .unwrap_or_default();
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{id}" Version="2.0" IssueInstant="2000-01-01T00:00:00Z"
    InResponseTo="{in_response_to}"{destination}>
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>"#
    )
}

fn signed_logout_response_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutResponse>, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    match binding {
        LogoutBinding::Post => {
            let signed = construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], None)?;
            Ok(BrowserInput::<LogoutResponse>::post(vec![FormField::new(
                "SAMLResponse",
                base64_encode(signed.as_bytes()),
            )]))
        }
        LogoutBinding::Redirect => {
            let octet = build_redirect_octet(ParserType::LogoutResponse, xml, None, RSA_SHA256)?;
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            let url = append_signature("https://receiver.example.com/slo", &octet, &signature);
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutResponse>::redirect(query))
        }
        LogoutBinding::SimpleSign => {
            let octet = format!("SAMLResponse={xml}&SigAlg={RSA_SHA256}");
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            Ok(BrowserInput::<LogoutResponse>::simple_sign(vec![
                FormField::new("SAMLResponse", base64_encode(xml.as_bytes())),
                FormField::new("SigAlg", RSA_SHA256),
                FormField::new("Signature", signature),
            ]))
        }
    }
}

fn unsigned_logout_response_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutResponse>, SamlError> {
    match binding {
        LogoutBinding::Post => Ok(BrowserInput::<LogoutResponse>::post(vec![FormField::new(
            "SAMLResponse",
            base64_encode(xml.as_bytes()),
        )])),
        LogoutBinding::Redirect => {
            let url = saml_rs::binding::build_redirect_url(
                "https://receiver.example.com/slo",
                ParserType::LogoutResponse,
                xml,
                None,
            )?;
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutResponse>::redirect(query))
        }
        LogoutBinding::SimpleSign => Err(SamlError::Invalid(
            "SimpleSign input requires its binding-level signature".into(),
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum ResponseProtection {
    Signed,
    UnsignedCompatibility,
}

fn finish_custom_logout_response(
    receiver_role: LocalSloRole,
    binding: LogoutBinding,
    destination: Option<&str>,
    protection: ResponseProtection,
    validation: SamlValidationContext<'_>,
) -> Result<LogoutCompleted, SamlError> {
    let sp = Saml::sp(match protection {
        ResponseProtection::Signed => sp_config()?,
        ResponseProtection::UnsignedCompatibility => {
            sp_config_with_validation(SpValidationPolicy::compatibility())?
        }
    })?;
    let idp = Saml::idp(match protection {
        ResponseProtection::Signed => idp_config()?,
        ResponseProtection::UnsignedCompatibility => {
            idp_config_with_validation(IdpValidationPolicy::compatibility())?
        }
    })?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response_id = format!("_{receiver_role:?}_{binding:?}_{protection:?}_response");

    match receiver_role {
        LocalSloRole::Sp => {
            let started =
                sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
            let xml = logout_response_xml(
                &response_id,
                IDP_ENTITY_ID,
                started.pending.id().as_str(),
                destination,
            );
            let input = match protection {
                ResponseProtection::Signed => signed_logout_response_input(&xml, binding)?,
                ResponseProtection::UnsignedCompatibility => {
                    unsigned_logout_response_input(&xml, binding)?
                }
            };
            sp.finish_slo(&idp_descriptor, &started.pending, input, validation)
        }
        LocalSloRole::Idp => {
            let started =
                idp.start_slo(&sp_descriptor, subject()?, start_slo_for_binding(binding))?;
            let xml = logout_response_xml(
                &response_id,
                SP_ENTITY_ID,
                started.pending.id().as_str(),
                destination,
            );
            let input = match protection {
                ResponseProtection::Signed => signed_logout_response_input(&xml, binding)?,
                ResponseProtection::UnsignedCompatibility => {
                    unsigned_logout_response_input(&xml, binding)?
                }
            };
            idp.finish_slo(&sp_descriptor, &started.pending, input, validation)
        }
    }
}

fn system_time(value: &str) -> Result<SystemTime, Box<dyn std::error::Error>> {
    Ok(SystemTime::from(OffsetDateTime::parse(value, &Rfc3339)?))
}

fn replace_response_issue_instant(
    fields: Vec<FormField>,
    replacement: Option<&str>,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    fields
        .into_iter()
        .map(|field| {
            if field.name() != "SAMLResponse" {
                return Ok(field);
            }
            let xml = String::from_utf8(base64_decode(field.value())?)?;
            let (before, after) = xml
                .split_once(" IssueInstant=\"")
                .ok_or("missing IssueInstant attribute")?;
            let (_, after) = after
                .split_once('"')
                .ok_or("unterminated IssueInstant attribute")?;
            let replacement = replacement
                .map(|value| format!(" IssueInstant=\"{value}\""))
                .unwrap_or_default();
            let xml = format!("{before}{replacement}{after}");
            Ok(FormField::new(
                "SAMLResponse",
                base64_encode(xml.as_bytes()),
            ))
        })
        .collect()
}

fn outbound_xml<Message>(
    outbound: &Outbound<Message>,
    message_field: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == message_field)
                .ok_or("missing SAML message")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                encoded.as_ref(),
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(
            &outbound.raw_context().context,
        )?)?),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
    }
}

fn start_idp_slo_with_template(template: String) -> Result<StartedSloResult, SamlError> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(300),
        Some(template),
        Credentials::default(),
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    match idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().signing(LogoutSigning::Sign),
    ) {
        Ok(_) => Ok(StartedSloResult::Succeeded),
        Err(error) => Ok(StartedSloResult::Failed(error)),
    }
}

enum StartedSloResult {
    Succeeded,
    Failed(SamlError),
}

struct SloExchange {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
    pending: PendingLogoutRequest,
    received: Received<LogoutRequest>,
    response_fields: Vec<FormField>,
}

fn sp_started_exchange() -> Result<SloExchange, SamlError> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;
    assert_eq!(started.outbound.raw_context().request_type, "SAMLRequest");

    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    assert_eq!(
        received.message().name_id().map(NameId::value),
        Some("alice@example.com")
    );
    assert_eq!(received.message().session_indexes().len(), 1);
    assert!(!received.message().raw_flow().saml_content.is_empty());

    let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    assert_eq!(response.raw_context().request_type, "SAMLResponse");
    let response_fields = post_fields(&response)?;

    Ok(SloExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields,
    })
}

fn value_str(value: &str) -> Value {
    Value::Str(value.to_string())
}

fn value_object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn sso_session() -> Result<SsoSession, SamlError> {
    SsoSession::try_from(FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            (
                "assertion",
                value_object(vec![
                    ("id", value_str("_assertion123")),
                    ("issueInstant", value_str("2024-01-01T00:00:01Z")),
                ]),
            ),
            ("issuer", value_str(IDP_ENTITY_ID)),
            ("nameID", value_str("alice@example.com")),
            (
                "sessionIndex",
                Value::Array(vec![
                    value_object(vec![
                        ("sessionIndex", value_str("_session123")),
                        ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                    ]),
                    value_object(vec![("sessionIndex", value_str("_session456"))]),
                ]),
            ),
        ]),
    })
}

#[test]
fn typed_slo_logout_request_session_index_follows_subject() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let with_session = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let with_session_xml = outbound_xml(&with_session.outbound, "SAMLRequest")?;
    assert!(with_session_xml.contains("<samlp:SessionIndex>_session123</samlp:SessionIndex>"));

    let without_session = sp.start_slo(
        &idp_descriptor,
        LogoutSubject::from_name_id(NameId::new("alice@example.com", None)),
        StartSlo::post(),
    )?;
    let without_session_xml = outbound_xml(&without_session.outbound, "SAMLRequest")?;
    assert!(!without_session_xml.contains("SessionIndex"));
    Ok(())
}

#[test]
fn typed_slo_start_and_response_bindings_use_peer_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let redirect = sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect())?;
    assert!(redirect
        .outbound
        .redirect_url()?
        .starts_with(IDP_SLO_REDIRECT));
    assert_eq!(redirect.pending.request_binding(), LogoutBinding::Redirect);

    let post = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    assert_eq!(post.outbound.post_form()?.action().as_str(), IDP_SLO_POST);
    assert_eq!(post.pending.request_binding(), LogoutBinding::Post);

    let simple_sign = sp.start_slo(&idp_descriptor, subject()?, StartSlo::simple_sign())?;
    let simple_sign_form = simple_sign.outbound.post_form()?;
    assert_eq!(simple_sign_form.action().as_str(), IDP_SLO_SIMPLESIGN);
    assert!(simple_sign_form.value("SigAlg").is_some());
    assert!(simple_sign_form.value("Signature").is_some());
    assert_eq!(
        simple_sign.pending.request_binding(),
        LogoutBinding::SimpleSign
    );

    let exchange = sp_started_exchange()?;
    let redirect_response =
        exchange
            .idp
            .respond_slo(&sp_descriptor, &exchange.received, RespondSlo::redirect())?;
    assert!(redirect_response
        .redirect_url()?
        .starts_with(SP_SLO_REDIRECT));

    let post_response =
        exchange
            .idp
            .respond_slo(&sp_descriptor, &exchange.received, RespondSlo::post())?;
    assert_eq!(post_response.post_form()?.action().as_str(), SP_SLO_POST);

    let simple_sign_response = exchange.idp.respond_slo(
        &sp_descriptor,
        &exchange.received,
        RespondSlo::simple_sign(),
    )?;
    let simple_sign_response_form = simple_sign_response.post_form()?;
    assert_eq!(
        simple_sign_response_form.action().as_str(),
        SP_SLO_SIMPLESIGN
    );
    assert!(simple_sign_response_form.value("SigAlg").is_some());
    assert!(simple_sign_response_form.value("Signature").is_some());
    Ok(())
}

#[test]
fn typed_slo_signs_front_channel_responses_despite_compatibility_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_validation(
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    let post = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    assert!(outbound_xml(&post, "SAMLResponse")?.contains("<ds:Signature"));

    let redirect = idp.respond_slo(&sp_descriptor, &received, RespondSlo::redirect())?;
    let redirect_url = Url::parse(redirect.redirect_url()?)?;
    assert!(redirect_url
        .query_pairs()
        .any(|(name, value)| name == "Signature" && !value.is_empty()));
    Ok(())
}

#[test]
fn typed_slo_rejects_peer_without_requested_logout_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .credentials(credentials())
            .validation(signed_authn_request_idp_validation())
            .build()?,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect()) {
        Err(SamlError::MissingMetadata(field)) => {
            assert_eq!(field, "SingleLogoutService");
            Ok(())
        }
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[test]
fn typed_slo_subject_can_come_from_sso_session() -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let subject = session.logout_subject().ok_or("missing logout subject")?;

    assert_eq!(subject.name_id().value(), "alice@example.com");
    assert_eq!(
        subject
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session123", "_session456"]
    );
    Ok(())
}

#[test]
fn typed_facade_starts_slo_redirect() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect())?;

    let redirect_url = started.outbound.redirect_url()?;
    assert!(redirect_url.starts_with(IDP_SLO_REDIRECT));
    assert_eq!(started.pending.id(), started.outbound.id());
    assert_eq!(started.pending.request_binding(), LogoutBinding::Redirect);
    assert_eq!(started.pending.peer_entity_id().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_facade_runs_sp_initiated_slo() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;

    assert_eq!(
        exchange.received.relay_state(),
        &RelayStateParam::try_from_option(Some("logout-state".to_string()))?
    );

    let completed = exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    )?;

    assert_eq!(completed.peer_entity_id().as_str(), IDP_ENTITY_ID);
    assert_eq!(
        completed.status(),
        Some(saml_rs::constants::status_code::SUCCESS)
    );
    let response = completed.response().ok_or("missing logout response")?;
    assert_eq!(response.in_response_to(), Some(exchange.pending.id()));
    assert_eq!(
        response.issue_instant().as_str(),
        response.issue_instant().as_str().trim()
    );
    assert!(response.issue_instant().as_str().ends_with('Z'));
    assert!(!completed
        .raw_flow()
        .ok_or("missing raw flow")?
        .saml_content
        .is_empty());
    assert_eq!(exchange.received.message().id(), exchange.pending.id());
    assert_eq!(exchange.sp_descriptor.entity_id().as_str(), SP_ENTITY_ID);
    assert_eq!(
        exchange
            .idp
            .raw_identity_provider()
            .metadata
            .get_entity_id(),
        Some(IDP_ENTITY_ID)
    );
    Ok(())
}

#[test]
fn typed_facade_rejects_missing_logout_response_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let response_fields = replace_response_issue_instant(exchange.response_fields, None)?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(response_fields),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "LogoutResponse is missing required unqualified attribute IssueInstant",
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected LogoutResponse IssueInstant error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_slo_checks_logout_request_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let mut cache = MemoryReplayCache::default();

    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, replay_key);
            Ok(())
        }
        other => Err(format!("expected LogoutRequest ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_expired_signed_logout_request_before_replay_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:00:00Z"));
    for binding in [
        LogoutBinding::Post,
        LogoutBinding::Redirect,
        LogoutBinding::SimpleSign,
    ] {
        let mut cache = MemoryReplayCache::default();
        let validation = SamlValidationContext::new(
            system_time("2026-07-15T12:00:00Z")?,
            ReplayPolicy::RequireCache(&mut cache),
        )
        .with_clock_skew(ClockSkew::strict());
        match receive_custom_logout_request(
            &template,
            binding,
            LocalSloRole::Idp,
            RequestProtection::Signed,
            validation,
        ) {
            Err(SamlError::TimeWindowInvalid { field }) => {
                assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
                assert!(cache.seen.is_empty());
            }
            other => {
                return Err(format!(
                    "expected expired signed LogoutRequest for {binding:?}, got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn new_validation_context_allows_five_minutes_on_logout_request_not_on_or_after(
) -> Result<(), Box<dyn std::error::Error>> {
    let within = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T11:55:01Z"));
    let boundary = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T11:55:00Z"));
    let now = system_time("2026-07-15T12:00:00Z")?;

    receive_custom_logout_request(
        &within,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility),
    )?;

    match receive_custom_logout_request(
        &boundary,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
            Ok(())
        }
        other => Err(format!(
            "expected LogoutRequest NotOnOrAfter exactly five minutes ago, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn clock_skew_strict_allows_no_logout_request_skew() -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T11:59:00Z"));

    match receive_custom_logout_request(
        &template,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        SamlValidationContext::new(
            system_time("2026-07-15T12:00:00Z")?,
            ReplayPolicy::DisabledForCompatibility,
        )
        .with_clock_skew(ClockSkew::strict()),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
            Ok(())
        }
        other => Err(format!("expected strict LogoutRequest rejection, got {other:?}").into()),
    }
}

#[test]
fn explicit_clock_skew_replaces_logout_request_five_minute_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let within = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T11:59:01Z"));
    let beyond = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T11:59:00Z"));
    let now = system_time("2026-07-15T12:00:00Z")?;
    let skew = ClockSkew::strict().with_not_on_or_after_millis(60_000);

    receive_custom_logout_request(
        &within,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility)
            .with_clock_skew(skew),
    )?;

    match receive_custom_logout_request(
        &beyond,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility)
            .with_clock_skew(skew),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
            Ok(())
        }
        other => Err(format!(
            "expected one-minute LogoutRequest NotOnOrAfter limit, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_rejects_signed_logout_request_without_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let xml = logout_request_xml(
                &format!("_missing_{receiver_role:?}_{binding:?}"),
                sender_entity_id(receiver_role),
                None,
            );
            let mut cache = MemoryReplayCache::default();
            match receive_crafted_logout_request(
                &xml,
                binding,
                receiver_role,
                RequestProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual, None);
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} missing Destination rejection for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_use_binding_specific_destination_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let received = match receiver_role {
                LocalSloRole::Idp => {
                    let started =
                        sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
                    idp.receive_slo(
                        &sp_descriptor,
                        logout_request_input(&started.outbound, binding)?,
                        validation(),
                    )?
                }
                LocalSloRole::Sp => {
                    let started =
                        idp.start_slo(&sp_descriptor, subject()?, start_slo_for_binding(binding))?;
                    sp.receive_slo(
                        &idp_descriptor,
                        logout_request_input(&started.outbound, binding)?,
                        validation(),
                    )?
                }
            };
            assert_eq!(
                received.message().destination().map(|url| url.as_str()),
                Some(receiver_role.endpoint(binding))
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facades_reject_mismatched_logout_request_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let xml = logout_request_xml(
                &format!("_mismatch_{receiver_role:?}_{binding:?}"),
                sender_entity_id(receiver_role),
                Some("https://wrong.example/slo"),
            );
            let mut cache = MemoryReplayCache::default();
            match receive_crafted_logout_request(
                &xml,
                binding,
                receiver_role,
                RequestProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual.as_deref(), Some("https://wrong.example/slo"));
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} DestinationMismatch for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_allow_unsigned_missing_destination_only_under_compatibility_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in UNSIGNED_COMPATIBILITY_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let xml = logout_request_xml(
                &format!("_unsigned_missing_{receiver_role:?}_{binding:?}"),
                sender_entity_id(receiver_role),
                None,
            );
            let received = receive_crafted_logout_request(
                &xml,
                binding,
                receiver_role,
                RequestProtection::UnsignedCompatibility,
                validation(),
            )?;
            assert_eq!(received.message().destination(), None);
        }
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_qualified_logout_request_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None).replace(
        r#"Destination="{Destination}""#,
        r#"samlp:Destination="{Destination}""#,
    );

    match receive_custom_logout_request(
        &template,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("attribute Destination on LogoutRequest must be unqualified") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected qualified Destination protocol-profile rejection, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_receive_slo_uses_not_on_or_after_deadline_without_generic_retention(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:01:00Z"));
    let mut cache = MemoryReplayCache::default();
    let validation = SamlValidationContext::new(
        system_time("2026-07-15T12:00:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    )
    .with_clock_skew(ClockSkew::strict().with_not_on_or_after_millis(30_000));

    let received = receive_custom_logout_request(
        &template,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        validation,
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert_eq!(
        cache.seen.get(&replay_key),
        Some(&system_time("2026-07-15T12:01:30Z")?)
    );
    assert_eq!(
        received.message().issue_instant().as_str(),
        "2000-01-01T00:00:00Z"
    );
    assert_eq!(
        received
            .message()
            .not_on_or_after()
            .map(saml_rs::SamlInstant::as_str),
        Some("2026-07-15T12:01:00Z")
    );
    Ok(())
}

#[test]
fn typed_facade_replay_deadline_includes_not_on_or_after_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:01:00Z"));
    let sp = Saml::sp(sp_config_with_logout_request_template(&template)?)?;
    let idp = Saml::idp(idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let first_now = system_time("2026-07-15T12:00:00Z")?;
    let mut cache = ExpiringReplayCache::new(first_now);
    let skew = ClockSkew::strict().with_not_on_or_after_millis(30_000);

    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        SamlValidationContext::new(first_now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert_eq!(
        cache.seen.get(&replay_key),
        Some(&system_time("2026-07-15T12:01:30Z")?)
    );

    cache.now = system_time("2026-07-15T12:01:01Z")?;
    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        SamlValidationContext::new(cache.now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    ) {
        Err(SamlError::ReplayDetected { key }) => assert_eq!(key, replay_key),
        other => return Err(format!("expected skew-retained replay, got {other:?}").into()),
    }

    cache.now = system_time("2026-07-15T12:01:30Z")?;
    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields),
        SamlValidationContext::new(cache.now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
            Ok(())
        }
        other => Err(format!("expected exact effective deadline rejection, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_slo_requires_replay_retention_for_logout_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?),
        validation,
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration error, got {other:?}").into()),
    }
}

fn recommended_logout_accept() -> LogoutPolicy {
    LogoutPolicy {
        requests: LogoutSignaturePolicy::RequireSigned,
        responses: LogoutSignaturePolicy::RequireSigned,
    }
}

#[test]
fn recommended_slo_does_not_store_replay_without_a_caller_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config_with_validation(SpValidationPolicy {
        logout: recommended_logout_accept(),
        ..SpValidationPolicy::compatibility()
    })?)?;
    let idp = Saml::idp(idp_config_with_validation(IdpValidationPolicy {
        logout: recommended_logout_accept(),
        ..IdpValidationPolicy::compatibility()
    })?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    assert!(!sp_descriptor.was_verified_with_pinned_certificates());
    assert!(!idp_descriptor.was_verified_with_pinned_certificates());

    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_fields = post_fields(&started.outbound)?;
    idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        validation(),
    )?;
    idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        validation(),
    )?;

    let mut request_cache = MemoryReplayCache::default();
    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        validation_with_cache(&mut request_cache),
    )?;
    let request_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert!(request_cache.seen.contains_key(&request_key));
    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields),
        validation_with_cache(&mut request_cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => assert_eq!(key, request_key),
        other => {
            return Err(format!(
                "expected LogoutRequest ReplayDetected from the caller cache, got {other:?}"
            )
            .into());
        }
    }

    let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    let response_fields = post_fields(&response)?;
    sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(response_fields.clone()),
        validation(),
    )?;
    sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(response_fields.clone()),
        validation(),
    )?;

    let mut response_cache = MemoryReplayCache::default();
    let completed = sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(response_fields.clone()),
        validation_with_cache(&mut response_cache),
    )?;
    let response_id = completed
        .response()
        .ok_or("missing logout response")?
        .id()
        .as_str();
    let response_key = format!("logout_response_id:{response_id}");
    assert!(response_cache.seen.contains_key(&response_key));
    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(response_fields),
        validation_with_cache(&mut response_cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, response_key);
            Ok(())
        }
        other => Err(format!(
            "expected LogoutResponse ReplayDetected from the caller cache, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_finish_slo_checks_logout_response_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = sp_started_exchange()?;
    let mut cache = MemoryReplayCache::default();

    let completed = exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let response = completed.response().ok_or("missing logout response")?;
    let replay_key = format!("logout_response_id:{}", response.id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, replay_key);
            Ok(())
        }
        other => Err(format!("expected LogoutResponse ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facades_accept_matching_logout_response_destination_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let endpoint = receiver_role.endpoint(binding);
            let completed = finish_custom_logout_response(
                receiver_role,
                binding,
                Some(endpoint),
                ResponseProtection::Signed,
                validation(),
            )?;
            assert_eq!(
                completed
                    .response()
                    .and_then(LogoutResponse::destination)
                    .map(|url| url.as_str()),
                Some(endpoint)
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_qualified_logout_response_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let xml = logout_response_xml(
        "_qualified_response_destination",
        IDP_ENTITY_ID,
        started.pending.id().as_str(),
        Some(SP_SLO_POST),
    )
    .replace(" Destination=", " samlp:Destination=");

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        signed_logout_response_input(&xml, LogoutBinding::Post)?,
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("attribute Destination on LogoutResponse must be unqualified") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected qualified LogoutResponse Destination rejection, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facades_reject_signed_logout_response_without_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match finish_custom_logout_response(
                receiver_role,
                binding,
                None,
                ResponseProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual, None);
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} missing response Destination rejection for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_reject_mismatched_logout_response_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match finish_custom_logout_response(
                receiver_role,
                binding,
                Some("https://wrong.example/slo"),
                ResponseProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual.as_deref(), Some("https://wrong.example/slo"));
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} response DestinationMismatch for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_allow_unsigned_logout_response_without_destination_in_compatibility_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in UNSIGNED_COMPATIBILITY_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let completed = finish_custom_logout_response(
                receiver_role,
                binding,
                None,
                ResponseProtection::UnsignedCompatibility,
                validation(),
            )?;
            assert_eq!(
                completed.response().and_then(LogoutResponse::destination),
                None
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facade_finish_slo_requires_replay_retention_for_logout_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation,
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_runs_idp_initiated_slo() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("idp-logout".to_string()))?;
    let started = idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;

    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = sp.receive_slo(&idp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), IDP_ENTITY_ID);

    let response = sp.respond_slo(&idp_descriptor, &received, RespondSlo::post())?;
    let completed = idp.finish_slo(
        &sp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(completed.peer_entity_id().as_str(), SP_ENTITY_ID);
    assert_eq!(
        completed
            .response()
            .and_then(LogoutResponse::in_response_to),
        Some(started.pending.id())
    );
    Ok(())
}

#[test]
fn typed_session_authority_slo_uses_configured_expiration_for_every_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let lifetime = Duration::from_secs(13 * 60);
    for binding in [
        LogoutBinding::Redirect,
        LogoutBinding::Post,
        LogoutBinding::SimpleSign,
    ] {
        let sp = Saml::sp(sp_config()?)?;
        let idp = Saml::idp(idp_config_with_issuance(
            lifetime,
            None,
            credentials(),
            signed_authn_request_idp_validation(),
        )?)?;
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = idp.start_slo(&sp_descriptor, subject()?, start_slo_for_binding(binding))?;
        let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
        let document = parse(&xml)?;
        let issue_instant = document
            .root
            .attr("IssueInstant")
            .ok_or("missing LogoutRequest IssueInstant")?;
        let expiration = document
            .root
            .attr("NotOnOrAfter")
            .ok_or("missing LogoutRequest NotOnOrAfter")?;
        let issue_time = OffsetDateTime::parse(issue_instant, &Rfc3339)?;
        let expiration_time = OffsetDateTime::parse(expiration, &Rfc3339)?;
        assert_eq!(expiration_time - issue_time, time::Duration::minutes(13));
        assert_eq!(
            started.pending.issued_at().map(|value| value.as_str()),
            Some(issue_instant)
        );
        assert_eq!(
            started.pending.expires_at().map(|value| value.as_str()),
            Some(expiration)
        );

        let received = sp.receive_slo(
            &idp_descriptor,
            logout_request_input(&started.outbound, binding)?,
            validation(),
        )?;
        assert_eq!(
            received
                .message()
                .not_on_or_after()
                .map(|value| value.as_str()),
            Some(expiration)
        );
    }
    Ok(())
}

#[test]
fn typed_session_authority_slo_signatures_cover_expiration_for_every_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [
        LogoutBinding::Redirect,
        LogoutBinding::Post,
        LogoutBinding::SimpleSign,
    ] {
        let sp = Saml::sp(sp_config()?)?;
        let idp = Saml::idp(idp_config_with_issuance(
            Duration::from_secs(13 * 60),
            None,
            credentials(),
            signed_authn_request_idp_validation(),
        )?)?;
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = idp.start_slo(
            &sp_descriptor,
            subject()?,
            start_slo_for_binding(binding).signing(LogoutSigning::Sign),
        )?;
        let expected_reason = match binding {
            LogoutBinding::Post => SignatureVerificationReason::XmlSignature,
            LogoutBinding::Redirect | LogoutBinding::SimpleSign => {
                SignatureVerificationReason::DetachedMessageSignature
            }
        };

        match sp.receive_slo(
            &idp_descriptor,
            tampered_logout_request_expiration_input(&started.outbound, binding)?,
            validation(),
        ) {
            Err(SamlError::SignatureVerification { reason }) if reason == expected_reason => {}
            other => {
                return Err(format!(
                    "expected {expected_reason:?} after tampering {binding:?} expiration, got {other:?}"
                )
                .into())
            }
        }
    }
    Ok(())
}

#[test]
fn one_typed_idp_issuance_lifetime_drives_sso_and_slo_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let lifetime = Duration::from_secs(17 * 60);
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        lifetime,
        None,
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let sso = idp.initiate_sso(
        &sp_descriptor,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::post(),
    )?;
    let sso_xml = outbound_xml(&sso, "SAMLResponse")?;
    let sso_document = parse(&sso_xml)?;
    let sso_issue_instant = sso_document
        .root
        .attr("IssueInstant")
        .ok_or("missing Response IssueInstant")?;
    let assertion = sso_document
        .root
        .children
        .iter()
        .find(|node| node.local_name == "Assertion")
        .ok_or("missing Assertion")?;
    let conditions_expiration = assertion
        .children
        .iter()
        .find(|node| node.local_name == "Conditions")
        .and_then(|node| node.attr("NotOnOrAfter"))
        .ok_or("missing Conditions NotOnOrAfter")?;
    let bearer_expiration = assertion
        .children
        .iter()
        .find(|node| node.local_name == "Subject")
        .and_then(|node| {
            node.children
                .iter()
                .find(|node| node.local_name == "SubjectConfirmation")
        })
        .and_then(|node| {
            node.children
                .iter()
                .find(|node| node.local_name == "SubjectConfirmationData")
        })
        .and_then(|node| node.attr("NotOnOrAfter"))
        .ok_or("missing SubjectConfirmationData NotOnOrAfter")?;
    assert_eq!(conditions_expiration, bearer_expiration);
    assert_eq!(
        OffsetDateTime::parse(conditions_expiration, &Rfc3339)?
            - OffsetDateTime::parse(sso_issue_instant, &Rfc3339)?,
        time::Duration::minutes(17)
    );

    let slo = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let slo_xml = outbound_xml(&slo.outbound, "SAMLRequest")?;
    let slo_document = parse(&slo_xml)?;
    let slo_issue_instant = slo_document
        .root
        .attr("IssueInstant")
        .ok_or("missing LogoutRequest IssueInstant")?;
    let slo_expiration = slo_document
        .root
        .attr("NotOnOrAfter")
        .ok_or("missing LogoutRequest NotOnOrAfter")?;
    assert_eq!(
        OffsetDateTime::parse(slo_expiration, &Rfc3339)?
            - OffsetDateTime::parse(slo_issue_instant, &Rfc3339)?,
        time::Duration::minutes(17)
    );
    Ok(())
}

#[test]
fn typed_session_authority_slo_preserves_configured_subsecond_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let lifetime = Duration::new(13, 123_456_789);
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        lifetime,
        None,
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    let document = parse(&xml)?;
    let issue_instant = document
        .root
        .attr("IssueInstant")
        .ok_or("missing LogoutRequest IssueInstant")?;
    let expiration = document
        .root
        .attr("NotOnOrAfter")
        .ok_or("missing LogoutRequest NotOnOrAfter")?;
    let issue_time = OffsetDateTime::parse(issue_instant, &Rfc3339)?;
    let expiration_time = OffsetDateTime::parse(expiration, &Rfc3339)?;

    assert_eq!(
        expiration_time - issue_time,
        time::Duration::new(13, 123_456_789)
    );
    assert_eq!(
        started.pending.issued_at().map(|value| value.as_str()),
        Some(issue_instant)
    );
    assert_eq!(
        started.pending.expires_at().map(|value| value.as_str()),
        Some(expiration)
    );
    Ok(())
}

#[test]
fn typed_session_authority_slo_defaults_to_five_minutes() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    let document = parse(&xml)?;
    let issue_instant = OffsetDateTime::parse(
        document
            .root
            .attr("IssueInstant")
            .ok_or("missing LogoutRequest IssueInstant")?,
        &Rfc3339,
    )?;
    let expiration = OffsetDateTime::parse(
        document
            .root
            .attr("NotOnOrAfter")
            .ok_or("missing LogoutRequest NotOnOrAfter")?,
        &Rfc3339,
    )?;

    assert_eq!(expiration - issue_instant, time::Duration::minutes(5));
    Ok(())
}

#[test]
fn typed_session_authority_pending_snapshot_round_trips_issuance_window(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let issued_at = started.pending.issued_at().cloned();
    let expires_at = started.pending.expires_at().cloned();
    let restored = PendingLogoutRequest::from_snapshot(started.pending.snapshot())?;
    assert_eq!(restored.issued_at(), issued_at.as_ref());
    assert_eq!(restored.expires_at(), expires_at.as_ref());

    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    let response = sp.respond_slo(&idp_descriptor, &received, RespondSlo::post())?;
    let completed = idp.finish_slo(
        &sp_descriptor,
        &restored,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    )?;
    assert_eq!(completed.peer_entity_id().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_session_participant_slo_keeps_generated_expiration_unset_for_every_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    for binding in [
        LogoutBinding::Redirect,
        LogoutBinding::Post,
        LogoutBinding::SimpleSign,
    ] {
        let started = sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
        let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
        assert!(!xml.contains("NotOnOrAfter="));
        assert!(started.pending.issued_at().is_none());
        assert!(started.pending.expires_at().is_none());
    }
    Ok(())
}

#[test]
fn typed_session_participant_preserves_unrecognized_expiration_placeholder(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("{NotOnOrAfter}"));
    let sp = Saml::sp(sp_config_with_logout_request_template(&template)?)?;
    let idp = Saml::idp(idp_config()?)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;

    assert_eq!(
        parse(&xml)?.root.attr("NotOnOrAfter"),
        Some("{NotOnOrAfter}")
    );
    Ok(())
}

#[test]
fn typed_session_authority_slo_reports_issuance_expiration_overflow_before_rendering(
) -> Result<(), Box<dyn std::error::Error>> {
    let malformed_template = SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(
        "Destination=\"{Destination}\"",
        "Corrupt=\"<\" Destination=\"{Destination}\"",
    );
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(i64::MAX as u64),
        Some(malformed_template),
        Credentials::default(),
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    match idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().signing(LogoutSigning::Sign),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::IdpIssuanceExpiration);
            Ok(())
        }
        other => Err(format!("expected IdpIssuanceExpiration error, got {other:?}").into()),
    }
}

#[test]
fn typed_session_authority_custom_logout_template_placeholder_succeeds(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(7 * 60),
        Some(SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.to_string()),
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;

    assert_eq!(
        received
            .message()
            .not_on_or_after()
            .map(|value| value.as_str()),
        started.pending.expires_at().map(|value| value.as_str())
    );
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_escapes_subject_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let name_id = "alice<&\"'@example.com";
    let session_index = "session<&\"'index";
    let subject = LogoutSubject::with_session_index(
        NameId::new(name_id, None),
        SessionIndex::try_new(session_index)?,
    );
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(7 * 60),
        Some(SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.to_string()),
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, subject, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(
        received.message().name_id().map(NameId::value),
        Some(name_id)
    );
    assert_eq!(
        received
            .message()
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec![session_index]
    );
    assert_eq!(
        received
            .message()
            .not_on_or_after()
            .map(|value| value.as_str()),
        started.pending.expires_at().map(|value| value.as_str())
    );
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_unmodeled_name_id_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    for qualifier in ["NameQualifier", "SPNameQualifier", "SPProvidedID"] {
        let template = SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(
            "Format=\"{NameIDFormat}\"",
            &format!("Format=\"{{NameIDFormat}}\" {qualifier}=\"unexpected\""),
        );
        assert_session_authority_template_rejected_before_signing(template)?;
    }
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_owned_identity_mutations_before_signing(
) -> Result<(), Box<dyn std::error::Error>> {
    let templates = [
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace("{ID}", "_wrong"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace("{IssueInstant}", "2030-01-01T00:00:00Z"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace("{Destination}", "https://wrong.example.com/slo"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace("{Issuer}", "wrong-issuer"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace("{NameID}", "wrong-name-id"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace("{SessionIndex}", "wrong-session"),
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace(
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            )
            .replace(
                "    <saml:NameID",
                "    <ds:Signature/>\n    <saml:NameID",
            ),
    ];
    for template in templates {
        match start_idp_slo_with_template(template)? {
            StartedSloResult::Failed(SamlError::MissingKey(name)) => {
                return Err(format!(
                    "template reached signing key lookup instead of failing validation: {name}"
                )
                .into())
            }
            StartedSloResult::Failed(_) => {}
            StartedSloResult::Succeeded => {
                return Err("expected template validation failure before signing".into())
            }
        }
    }
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_preserves_valid_extensions(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
        .replace(
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ext=\"urn:example:logout\"",
        )
        .replace(
            "    <saml:NameID",
            "    <samlp:Extensions><ext:Audit>preserve-me</ext:Audit></samlp:Extensions>\n    <saml:NameID",
        );
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(7 * 60),
        Some(template),
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert!(xml.contains("<ext:Audit>preserve-me</ext:Audit>"));
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(
        received.message().name_id().map(NameId::value),
        Some("alice@example.com")
    );
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_allows_omitted_unspecified_name_id_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let template =
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(" Format=\"{NameIDFormat}\"", "");
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(7 * 60),
        Some(template),
        credentials(),
        signed_authn_request_idp_validation(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(received.message().name_id().and_then(NameId::format), None);
    Ok(())
}

#[test]
fn typed_session_authority_custom_logout_template_requires_explicit_name_id_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let template =
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(" Format=\"{NameIDFormat}\"", "");
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .name_id_format(NameIdFormat::EmailAddress)
            .credentials(Credentials::default())
            .issuance_lifetime(Duration::from_secs(7 * 60))
            .validation(IdpValidationPolicy::compatibility())
            .templates(TemplatePolicy {
                logout_request_template: Some(template),
                ..TemplatePolicy::default()
            })
            .build()?,
    )?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    match idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().signing(LogoutSigning::Sign),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("missing expected Format") => {
            Ok(())
        }
        other => Err(format!(
            "expected missing explicit NameID Format before signing, got {other:?}"
        )
        .into()),
    }
}

fn assert_session_authority_template_rejected_before_signing(
    template: String,
) -> Result<(), Box<dyn std::error::Error>> {
    match start_idp_slo_with_template(template)? {
        StartedSloResult::Failed(
            SamlError::ProtocolProfile(_) | SamlError::Xml(_) | SamlError::Invalid(_),
        ) => Ok(()),
        StartedSloResult::Failed(other) => Err(format!(
            "expected template validation failure before signing, got {other:?}"
        )
        .into()),
        StartedSloResult::Succeeded => Err("expected template validation failure".into()),
    }
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_omitted_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_session_authority_template_rejected_before_signing(
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace("\n    NotOnOrAfter=\"{NotOnOrAfter}\"", ""),
    )
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_duplicate_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_session_authority_template_rejected_before_signing(
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(
            "NotOnOrAfter=\"{NotOnOrAfter}\"",
            "NotOnOrAfter=\"{NotOnOrAfter}\" NotOnOrAfter=\"{NotOnOrAfter}\"",
        ),
    )
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_qualified_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_session_authority_template_rejected_before_signing(
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace(
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:x=\"urn:example:qualified\"",
            )
            .replace("NotOnOrAfter=", "x:NotOnOrAfter="),
    )
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_malformed_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_session_authority_template_rejected_before_signing(
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace(
            "Destination=\"{Destination}\"",
            "Corrupt=\"<\" Destination=\"{Destination}\"",
        ),
    )
}

#[test]
fn typed_session_authority_custom_logout_template_rejects_hard_coded_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_session_authority_template_rejected_before_signing(
        SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.replace("{NotOnOrAfter}", "2000-01-01T00:00:00Z"),
    )
}

#[test]
fn typed_facade_rejects_slo_pending_peer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let other_idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://other-idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .credentials(credentials())
            .validation(signed_authn_request_idp_validation())
            .build()?,
    )?;
    let other_descriptor = IdpDescriptor::from_metadata_xml(
        other_idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match exchange.sp.finish_slo(
        &other_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-idp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_response_binding_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let pending = PendingLogoutRequest::try_new(
        exchange.pending.id().clone(),
        exchange.pending.relay_state().clone(),
        LogoutBinding::SimpleSign,
        exchange.pending.peer_entity_id().clone(),
    )?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::UnsupportedBinding { binding }) => {
            assert_eq!(binding, saml_rs::raw::Binding::Post);
            Ok(())
        }
        other => Err(format!("expected UnsupportedBinding, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_relay_state_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = sp_started_exchange()?;
    for field in &mut exchange.response_fields {
        if field.name() == "RelayState" {
            *field = FormField::new("RelayState", "other-logout");
        }
    }

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
            );
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("other-logout".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_wrong_pending_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let mut snapshot: PendingSnapshot<LogoutRequest> = exchange.pending.snapshot();
    snapshot.id = "_different_logout".to_string();
    let wrong_pending = PendingLogoutRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &wrong_pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different_logout"));
            assert_eq!(actual.as_deref(), Some(exchange.pending.id().as_str()));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_unexpected_slo_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::try_from_option(Some(
            "unexpected".to_string(),
        ))?),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(expected, RelayStateParam::Absent);
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("unexpected".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_respond_slo_to_suppress_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::absent()),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
            );
            assert_eq!(actual, RelayStateParam::Absent);
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_respond_slo_to_override_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::try_from_option(Some(
            "override".to_string(),
        ))?),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
            );
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("override".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_custom_logout_response_in_response_to_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(bad_template_idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    match idp.respond_slo(&sp_descriptor, &received, RespondSlo::post()) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some(received.message().id().as_str()));
            assert_eq!(actual.as_deref(), Some("_wrong"));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_custom_logout_response_profile_before_correlation(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(bad_profile_template_idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    match idp.respond_slo(&sp_descriptor, &received, RespondSlo::post()) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected custom LogoutResponse profile error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_explicit_unsigned_logout_request_for_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;

    assert!(started.outbound.post_form()?.value("SAMLRequest").is_some());
    Ok(())
}

fn status_element(xml: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let start = xml.find("<samlp:Status>").ok_or("missing Status")?;
    let rest = &xml[start..];
    let end = rest.find("</samlp:Status>").ok_or("missing Status end")?;
    Ok(&rest[..end + "</samlp:Status>".len()])
}

#[test]
fn typed_session_participant_logout_response_carries_caller_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    let response = sp.respond_slo(
        &idp_descriptor,
        &received,
        RespondSlo::post().status(Status::responder().with_subordinate(
            SubordinateStatusCode::try_new(saml_rs::constants::status_code::REQUEST_DENIED)?,
        )),
    )?;

    let response_xml = outbound_xml(&response, "SAMLResponse")?;
    let status = status_element(&response_xml)?;
    assert_eq!(
        status,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\">",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:RequestDenied\"/>",
            "</samlp:StatusCode>",
            "</samlp:Status>"
        )
    );
    Ok(())
}

fn success_status_element() -> &'static str {
    concat!(
        "<samlp:Status>",
        "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>",
        "</samlp:Status>"
    )
}

#[test]
fn typed_logout_response_omits_status_as_success_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let participant_request = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let participant_received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&participant_request.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    let participant_response =
        sp.respond_slo(&idp_descriptor, &participant_received, RespondSlo::post())?;
    assert_eq!(
        status_element(&outbound_xml(&participant_response, "SAMLResponse")?)?,
        success_status_element()
    );

    let authority_request = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let authority_received = idp.receive_slo(
        &sp_descriptor,
        logout_request_input(&authority_request.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    let authority_response =
        idp.respond_slo(&sp_descriptor, &authority_received, RespondSlo::post())?;
    assert_eq!(
        status_element(&outbound_xml(&authority_response, "SAMLResponse")?)?,
        success_status_element()
    );
    Ok(())
}

#[test]
fn typed_session_authority_logout_response_carries_caller_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let received = idp.receive_slo(
        &sp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;

    let own_session_failed = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().status(Status::responder()),
    )?;
    assert_eq!(
        status_element(&outbound_xml(&own_session_failed, "SAMLResponse")?)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\"/>",
            "</samlp:Status>"
        )
    );

    let partial = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post()
            .status(Status::success().with_subordinate(SubordinateStatusCode::partial_logout())),
    )?;
    assert_eq!(
        status_element(&outbound_xml(&partial, "SAMLResponse")?)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:PartialLogout\"/>",
            "</samlp:StatusCode>",
            "</samlp:Status>"
        )
    );
    Ok(())
}

#[test]
fn typed_logout_response_carries_caller_defined_subordinate_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    let response = sp.respond_slo(
        &idp_descriptor,
        &received,
        RespondSlo::post().status(Status::requester().with_subordinate(
            SubordinateStatusCode::try_new("urn:example:logout:local-failure")?,
        )),
    )?;

    assert_eq!(
        status_element(&outbound_xml(&response, "SAMLResponse")?)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\">",
            "<samlp:StatusCode Value=\"urn:example:logout:local-failure\"/>",
            "</samlp:StatusCode>",
            "</samlp:Status>"
        )
    );
    Ok(())
}

#[test]
fn typed_logout_response_rejects_a_subordinate_status_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    for uri in [
        "",
        "relative",
        "urn:example:has space",
        "https://idp.example/status?a=1&b=2",
    ] {
        match SubordinateStatusCode::try_new(uri) {
            Err(SamlError::Invalid(message))
                if message.contains("absolute URI without whitespace or XML attribute markup") => {}
            other => {
                return Err(format!(
                    "expected invalid subordinate status for {uri}, got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn typed_logout_response_template_carries_only_the_top_level_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_logout_response_template(
        saml_rs::template::LOGOUT_RESPONSE_TEMPLATE.to_string(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let received = idp.receive_slo(
        &sp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;

    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().status(Status::version_mismatch()),
    )?;
    let response_xml = outbound_xml(&response, "SAMLResponse")?;
    let status = status_element(&response_xml)?;
    assert!(status.contains("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"));
    assert_eq!(status.matches("<samlp:StatusCode").count(), 1);

    match idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post()
            .status(Status::success().with_subordinate(SubordinateStatusCode::partial_logout())),
    ) {
        Err(SamlError::Invalid(message))
            if message.contains("cannot carry a subordinate status code") =>
        {
            Ok(())
        }
        other => Err(format!("expected template subordinate rejection, got {other:?}").into()),
    }
}

#[test]
fn typed_receive_slo_returns_principal_and_every_session_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let subject = LogoutSubject::new(
        NameId::new("alice@example.com", None),
        vec![
            SessionIndex::try_new("_session-one")?,
            SessionIndex::try_new("_session-two")?,
        ],
    );

    let from_participant = sp.start_slo(&idp_descriptor, subject.clone(), StartSlo::post())?;
    let received_by_authority = idp.receive_slo(
        &sp_descriptor,
        logout_request_input(&from_participant.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(
        received_by_authority.message().name_id().map(NameId::value),
        Some("alice@example.com")
    );
    assert_eq!(
        received_by_authority
            .message()
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session-one", "_session-two"]
    );

    let from_authority = idp.start_slo(&sp_descriptor, subject, StartSlo::post())?;
    let received_by_participant = sp.receive_slo(
        &idp_descriptor,
        logout_request_input(&from_authority.outbound, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(
        received_by_participant
            .message()
            .name_id()
            .map(NameId::value),
        Some("alice@example.com")
    );
    assert_eq!(
        received_by_participant
            .message()
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session-one", "_session-two"]
    );
    Ok(())
}

#[test]
fn typed_logout_response_template_must_carry_the_supplied_top_level_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = saml_rs::template::LOGOUT_RESPONSE_TEMPLATE
        .replace("{StatusCode}", saml_rs::constants::status_code::SUCCESS);
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_logout_response_template(template)?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let received = idp.receive_slo(
        &sp_descriptor,
        logout_request_input(&started.outbound, LogoutBinding::Post)?,
        validation(),
    )?;

    match idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().status(Status::responder()),
    ) {
        Err(SamlError::Invalid(message))
            if message.contains("did not carry the supplied top-level status code") =>
        {
            Ok(())
        }
        other => Err(format!("expected template status mismatch, got {other:?}").into()),
    }
}

const QUALIFIED_NAME_ID: &str = "pseudonym-7f3a";
const QUALIFIED_NAME_QUALIFIER: &str = "https://idp.example.com/metadata";
const QUALIFIED_SP_NAME_QUALIFIER: &str = "https://sp.example.com/metadata";
const QUALIFIED_SP_PROVIDED_ID: &str = "sp-alias-42";

const QUALIFIED_LOGOUT_REQUEST_TEMPLATE: &str = r#"
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}"
    NotOnOrAfter="{NotOnOrAfter}" Destination="{Destination}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <saml:NameID NameQualifier="{NameQualifier}" SPNameQualifier="{SPNameQualifier}" Format="{NameIDFormat}" SPProvidedID="{SPProvidedID}">{NameID}</saml:NameID>
    <samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>
"#;

fn qualified_subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        NameId::with_qualifiers(
            QUALIFIED_NAME_ID,
            Some(NameIdFormat::Persistent),
            Some(QUALIFIED_NAME_QUALIFIER.to_string()),
            Some(QUALIFIED_SP_NAME_QUALIFIER.to_string()),
            Some(QUALIFIED_SP_PROVIDED_ID.to_string()),
        ),
        SessionIndex::try_new("_session123")?,
    ))
}

fn qualified_name_id_attrs() -> Vec<(String, String)> {
    let mut attrs = vec![
        (
            "Format".to_string(),
            NameIdFormat::Persistent.as_uri().to_string(),
        ),
        (
            "NameQualifier".to_string(),
            QUALIFIED_NAME_QUALIFIER.to_string(),
        ),
        (
            "SPNameQualifier".to_string(),
            QUALIFIED_SP_NAME_QUALIFIER.to_string(),
        ),
        (
            "SPProvidedID".to_string(),
            QUALIFIED_SP_PROVIDED_ID.to_string(),
        ),
    ];
    attrs.sort();
    attrs
}

type NameIdView = (String, Vec<(String, String)>);

fn logout_request_name_id(xml: &str) -> Result<NameIdView, Box<dyn std::error::Error>> {
    let document = parse(xml)?;
    let name_id = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "NameID")
        .ok_or("missing LogoutRequest NameID")?;
    let mut attrs = name_id.attrs.clone();
    attrs.sort();
    Ok((name_id.text.clone(), attrs))
}

#[test]
fn typed_slo_logout_request_keeps_name_id_format_and_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for binding in ALL_LOGOUT_BINDINGS {
        let started = sp.start_slo(
            &idp_descriptor,
            qualified_subject()?,
            start_slo_for_binding(binding),
        )?;
        let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
        assert_eq!(
            logout_request_name_id(&xml)?,
            (QUALIFIED_NAME_ID.to_string(), qualified_name_id_attrs()),
        );
    }

    let started = idp.start_slo(&sp_descriptor, qualified_subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        (QUALIFIED_NAME_ID.to_string(), qualified_name_id_attrs()),
    );
    Ok(())
}

#[test]
fn typed_slo_logout_request_without_subject_format_omits_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        ("alice@example.com".to_string(), Vec::new())
    );
    Ok(())
}

#[test]
fn typed_session_authority_logout_request_without_subject_format_sends_configured_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .name_id_format(NameIdFormat::EmailAddress)
            .credentials(credentials())
            .validation(IdpValidationPolicy::compatibility())
            .build()?,
    )?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        (
            "alice@example.com".to_string(),
            vec![(
                "Format".to_string(),
                NameIdFormat::EmailAddress.as_uri().to_string()
            )],
        ),
    );
    Ok(())
}

#[test]
fn typed_slo_logout_request_template_renders_name_id_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(300),
        Some(QUALIFIED_LOGOUT_REQUEST_TEMPLATE.to_string()),
        credentials(),
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, qualified_subject()?, StartSlo::post())?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        (QUALIFIED_NAME_ID.to_string(), qualified_name_id_attrs()),
    );

    let started = idp.start_slo(
        &sp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new(QUALIFIED_NAME_ID, Some(NameIdFormat::Persistent)),
            SessionIndex::try_new("_session123")?,
        ),
        StartSlo::post(),
    )?;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        (
            QUALIFIED_NAME_ID.to_string(),
            vec![(
                "Format".to_string(),
                NameIdFormat::Persistent.as_uri().to_string()
            )],
        ),
    );
    Ok(())
}

#[test]
fn typed_slo_logout_request_template_without_qualifier_placeholders_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_issuance(
        Duration::from_secs(300),
        Some(SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE.to_string()),
        credentials(),
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let result = idp.start_slo(&sp_descriptor, qualified_subject()?, StartSlo::post());
    assert!(
        matches!(&result, Err(SamlError::ProtocolProfile(message)) if message.contains("NameQualifier")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn typed_slo_logout_request_template_fixed_format_must_match_a_subject_without_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = Saml::idp(idp_config()?)?;
    let start = |format: &NameIdFormat| -> Result<_, Box<dyn std::error::Error>> {
        let template = SESSION_AUTHORITY_LOGOUT_REQUEST_TEMPLATE
            .replace("\n    NotOnOrAfter=\"{NotOnOrAfter}\"", "")
            .replace("{NameIDFormat}", format.as_uri());
        let sp = Saml::sp(sp_config_with_logout_request_template(&template)?)?;
        let (_, idp_descriptor) = descriptors(&sp, &idp)?;
        Ok(sp.start_slo(
            &idp_descriptor,
            subject()?,
            StartSlo::post().apply_single_logout_generation_rules(),
        ))
    };

    let started = start(&NameIdFormat::Unspecified)??;
    let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
    assert_eq!(
        logout_request_name_id(&xml)?,
        (
            "alice@example.com".to_string(),
            vec![(
                "Format".to_string(),
                NameIdFormat::Unspecified.as_uri().to_string()
            )],
        ),
    );

    let result = start(&NameIdFormat::EmailAddress)?;
    assert!(
        matches!(&result, Err(SamlError::ProtocolProfile(message)) if message.contains("NameID Format")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn typed_slo_subject_from_sso_session_keeps_name_id_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion123" Version="2.0" IssueInstant="2024-01-01T00:00:01Z"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><saml:Subject><saml:NameID NameQualifier="{QUALIFIED_NAME_QUALIFIER}" SPNameQualifier="{QUALIFIED_SP_NAME_QUALIFIER}" Format="{format}" SPProvidedID="{QUALIFIED_SP_PROVIDED_ID}">{QUALIFIED_NAME_ID}</saml:NameID></saml:Subject><saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_session123"/></saml:Assertion>"#,
        format = NameIdFormat::Persistent.as_uri(),
    );
    let response = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{assertion}</samlp:Response>"#,
    );
    let session = SsoSession::try_from(FlowResult {
        extract: extract(&response, &login_response_fields(&assertion))?,
        saml_content: response,
        sig_alg: None,
    })?;
    let subject = session.logout_subject().ok_or("missing logout subject")?;

    assert_eq!(subject.name_id(), qualified_subject()?.name_id());
    Ok(())
}
