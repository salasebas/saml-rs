//! Typed SSO acceptance of assertion conditions and every assertion in a response.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::collections::HashMap;
use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::constants::name_id_format::{PERSISTENT, UNSPECIFIED};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{
    construct_message_signature, construct_saml_signature, keys::load_private_key,
};
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, Outbound,
    PendingAuthnRequest, PrivateKeyPem, ReplayCache, ReplayKey, ReplayPolicy, RespondSso, Saml,
    SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
    SsoResponse, SsoSession, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLE: &str = "https://sp.example.com/acs/simple";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const OTHER_AUDIENCE: &str = "https://other.example/metadata";
const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

struct Exchange {
    sp: Saml<saml_rs::Sp>,
    idp_descriptor: IdpDescriptor,
    pending: Option<PendingAuthnRequest>,
    response_fields: Vec<FormField>,
}

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

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
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

fn exchange_for(
    sp_validation: SpValidationPolicy,
    unsolicited: bool,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
            .credentials(credentials())
            .validation(sp_validation)
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    if unsolicited {
        let response = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
        return Ok(Exchange {
            sp,
            idp_descriptor,
            pending: None,
            response_fields: post_fields(&response)?,
        });
    }
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
    Ok(Exchange {
        sp,
        idp_descriptor,
        pending: Some(started.pending),
        response_fields: post_fields(&response)?,
    })
}

fn response_xml(fields: &[FormField]) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = fields
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(base64_decode(encoded)?)?)
}

fn fields_with_xml(
    mut fields: Vec<FormField>,
    xml: &str,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let field = fields
        .iter_mut()
        .find(|field| field.name() == "SAMLResponse")
        .ok_or("missing SAMLResponse")?;
    *field = FormField::new("SAMLResponse", base64_encode(xml.as_bytes()));
    Ok(fields)
}

fn strip_embedded_signatures(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut rest = xml;
    let mut stripped = String::new();
    while let Some(start) = rest.find("<ds:Signature") {
        stripped.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find("</ds:Signature>")
            .ok_or("unterminated XML signature")?;
        rest = &after[end + "</ds:Signature>".len()..];
    }
    stripped.push_str(rest);
    Ok(stripped)
}

fn resign_response(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVKEY, None)?;
    Ok(construct_saml_signature(
        &strip_embedded_signatures(xml)?,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn insert_after_audience_restriction(
    xml: &str,
    element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let needle = "</saml:AudienceRestriction>";
    let at = xml.find(needle).ok_or("missing audience restriction")?;
    let mut altered = xml.to_string();
    altered.insert_str(at + needle.len(), element);
    Ok(altered)
}

fn duplicate_assertion(xml: &str, new_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let end_tag = "</saml:Assertion>";
    let relative_end = xml[start..].find(end_tag).ok_or("unterminated assertion")?;
    let end = start + relative_end + end_tag.len();
    let mut clone = xml[start..end].to_string();
    let id_at = clone.find("ID=\"").ok_or("missing assertion ID")?;
    let value_start = id_at + "ID=\"".len();
    let value_end = clone[value_start..]
        .find('"')
        .ok_or("unterminated assertion ID")?
        + value_start;
    clone.replace_range(value_start..value_end, new_id);
    let insert_at = xml
        .rfind("</samlp:Response>")
        .ok_or("missing response end")?;
    let mut altered = xml.to_string();
    altered.insert_str(insert_at, &clone);
    Ok(altered)
}

fn replace_in_last_assertion(
    xml: &str,
    from: &str,
    to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let assertion = xml.rfind("<saml:Assertion").ok_or("missing assertion")?;
    let at = xml[assertion..]
        .find(from)
        .ok_or("missing text in the last assertion")?
        + assertion;
    let mut altered = xml.to_string();
    altered.replace_range(at..at + from.len(), to);
    Ok(altered)
}

fn assertion_ids(xml: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut ids = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<saml:Assertion") {
        let open_end = rest[start..].find('>').ok_or("unterminated assertion")?;
        let opening = &rest[start..start + open_end];
        let id_at = opening.find("ID=\"").ok_or("missing assertion ID")?;
        let value = &opening[id_at + "ID=\"".len()..];
        let value_end = value.find('"').ok_or("unterminated assertion ID")?;
        ids.push(value[..value_end].to_string());
        rest = &rest[start + open_end..];
    }
    Ok(ids)
}

fn accept(exchange: &Exchange, xml: &str) -> Result<SsoSession, Box<dyn std::error::Error>> {
    accept_with(exchange, xml, validation())
}

fn accept_with<'a>(
    exchange: &Exchange,
    xml: &str,
    validation: SamlValidationContext<'a>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let fields = fields_with_xml(exchange.response_fields.clone(), xml)?;
    let input = BrowserInput::<SsoResponse>::post(fields);
    if let Some(pending) = &exchange.pending {
        return Ok(exchange
            .sp
            .finish_sso(&exchange.idp_descriptor, pending, input, validation)?);
    }
    Ok(exchange
        .sp
        .accept_unsolicited_sso(&exchange.idp_descriptor, input, validation)?)
}

fn resigned(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    resign_response(xml)
}

fn replace_element_id(
    xml: &str,
    element: &str,
    new_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find(element).ok_or("missing element")?;
    let id_at = xml[start..].find("ID=\"").ok_or("missing element ID")? + start;
    let value_start = id_at + "ID=\"".len();
    let value_end = xml[value_start..]
        .find('"')
        .ok_or("unterminated element ID")?
        + value_start;
    let mut altered = xml.to_string();
    altered.replace_range(value_start..value_end, new_id);
    Ok(altered)
}

fn set_name_id_format(
    xml: &str,
    index: usize,
    format: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut rest = xml;
    let mut offset = 0;
    for _ in 0..index {
        let start = rest.find("<saml:NameID").ok_or("missing NameID")?;
        let end = rest[start..].find('>').ok_or("unterminated NameID")? + start;
        offset += end + 1;
        rest = &xml[offset..];
    }
    let start = xml[offset..].find("<saml:NameID").ok_or("missing NameID")? + offset;
    let end = xml[start..].find('>').ok_or("unterminated NameID")? + start;
    let opening = xml[start..=end].to_string();
    let replaced = match (opening.find(" Format=\""), format) {
        (Some(format_at), Some(format)) => {
            let value_start = format_at + " Format=\"".len();
            let value_end = opening[value_start..]
                .find('"')
                .ok_or("unterminated Format")?
                + value_start;
            let mut opening = opening;
            opening.replace_range(value_start..value_end, format);
            opening
        }
        (Some(format_at), None) => {
            let value_start = format_at + " Format=\"".len();
            let value_end = opening[value_start..]
                .find('"')
                .ok_or("unterminated Format")?
                + value_start
                + 1;
            let mut opening = opening;
            opening.replace_range(format_at..value_end, "");
            opening
        }
        (None, Some(format)) => {
            opening.replace("<saml:NameID", &format!("<saml:NameID Format=\"{format}\""))
        }
        (None, None) => opening,
    };
    let mut altered = xml.to_string();
    altered.replace_range(start..=end, &replaced);
    Ok(altered)
}

fn simple_sign_fields(
    fields: &[FormField],
    xml: &str,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let sig_alg = fields
        .iter()
        .find(|field| field.name() == "SigAlg")
        .map(FormField::value)
        .ok_or("missing SigAlg")?;
    let relay_state = fields
        .iter()
        .find(|field| field.name() == "RelayState")
        .map(FormField::value);
    let octet = match relay_state {
        Some(relay_state) => {
            format!("SAMLResponse={xml}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("SAMLResponse={xml}&SigAlg={sig_alg}"),
    };
    let key = load_private_key(PRIVKEY, None)?;
    let signature = construct_message_signature(&octet, &key, sig_alg)?;
    let mut signed = vec![
        FormField::new("SAMLResponse", base64_encode(xml.as_bytes())),
        FormField::new("SigAlg", sig_alg),
        FormField::new("Signature", signature),
    ];
    if let Some(relay_state) = relay_state {
        signed.insert(1, FormField::new("RelayState", relay_state));
    }
    Ok(signed)
}

fn exchange_simple_sign() -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
            .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLE)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::simple_sign())?;
    Ok(Exchange {
        sp,
        idp_descriptor,
        pending: None,
        response_fields: post_fields(&response)?,
    })
}

fn accept_simple_sign(
    exchange: &Exchange,
    xml: &str,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let fields = simple_sign_fields(&exchange.response_fields, xml)?;
    Ok(exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        BrowserInput::<SsoResponse>::simple_sign(fields),
        validation(),
    )?)
}

#[cfg(feature = "crypto-rustcrypto")]
fn sign_first_assertion(xml: &str, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVKEY, None)?;
    Ok(construct_saml_signature(
        xml,
        false,
        &key,
        CERT,
        algorithm,
        &[],
        None,
    )?)
}

#[cfg(feature = "crypto-rustcrypto")]
fn move_last_assertion_first(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let first = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let last = xml.rfind("<saml:Assertion").ok_or("missing assertion")?;
    if first == last {
        return Err("expected two assertions".into());
    }
    let end_tag = "</saml:Assertion>";
    let relative_end = xml[last..].find(end_tag).ok_or("unterminated assertion")?;
    let end = last + relative_end + end_tag.len();
    let assertion = xml[last..end].to_string();
    let mut moved = xml.to_string();
    moved.replace_range(last..end, "");
    let insert_at = moved.find("<saml:Assertion").ok_or("missing assertion")?;
    moved.insert_str(insert_at, &assertion);
    Ok(moved)
}

fn drop_assertion_namespace_declaration(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let open_end = xml[start..].find('>').ok_or("unterminated assertion")? + start;
    let attr = " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";
    let relative = xml[start..open_end]
        .find(attr)
        .ok_or("missing assertion namespace declaration")?;
    let at = start + relative;
    let mut altered = xml.to_string();
    altered.replace_range(at..at + attr.len(), "");
    Ok(altered)
}

fn expect_unrecognized(
    result: Result<SsoSession, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::UnrecognizedCondition { element }) if element == "Condition" => Ok(()),
            _ => Err(format!("expected UnrecognizedCondition, got {error}").into()),
        },
        Ok(_) => Err("expected UnrecognizedCondition".into()),
    }
}

#[test]
fn finish_sso_rejects_an_unknown_condition() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&exchange.response_fields)?,
        "<saml:Condition/>",
    )?)?;
    expect_unrecognized(accept(&exchange, &xml))
}

#[test]
fn accept_unsolicited_sso_rejects_an_unknown_condition() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), true)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&exchange.response_fields)?,
        "<saml:Condition/>",
    )?)?;
    expect_unrecognized(accept(&exchange, &xml))
}

#[test]
fn compatibility_still_rejects_an_unknown_condition() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::compatibility(), false)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&exchange.response_fields)?,
        "<saml:Condition/>",
    )?)?;
    expect_unrecognized(accept(&exchange, &xml))
}

#[test]
fn finish_sso_accepts_proxy_restriction() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&exchange.response_fields)?,
        "<saml:ProxyRestriction Count=\"0\"/>",
    )?)?;
    let session = accept(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn accept_unsolicited_sso_accepts_proxy_restriction() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), true)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&exchange.response_fields)?,
        "<saml:ProxyRestriction Count=\"0\"/>",
    )?)?;
    let session = accept(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn one_time_use_is_accepted_and_a_later_exchange_succeeds() -> Result<(), Box<dyn std::error::Error>>
{
    let first = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&insert_after_audience_restriction(
        &response_xml(&first.response_fields)?,
        "<saml:OneTimeUse/>",
    )?)?;
    let session = accept(&first, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let later = exchange_for(SpValidationPolicy::recommended(), false)?;
    let later_session = accept(&later, &response_xml(&later.response_fields)?)?;
    assert_ne!(
        session.assertion_id().as_str(),
        later_session.assertion_id().as_str()
    );
    Ok(())
}

#[test]
fn audience_restrictions_are_conjoined_and_audiences_are_alternatives(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let original = response_xml(&exchange.response_fields)?;

    let both = resigned(&insert_after_audience_restriction(
        &original,
        &format!(
            "<saml:AudienceRestriction><saml:Audience>{SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction>"
        ),
    )?)?;
    assert_eq!(
        accept(&exchange, &both)?.name_id().value(),
        "alice@example.com"
    );

    let alternatives = resigned(&original.replacen(
        &format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>"),
        &format!(
            "<saml:Audience>{SP_ENTITY_ID}</saml:Audience><saml:Audience>{OTHER_AUDIENCE}</saml:Audience>"
        ),
        1,
    ))?;
    assert_eq!(
        accept(&exchange, &alternatives)?.name_id().value(),
        "alice@example.com"
    );

    let missing = resigned(&insert_after_audience_restriction(
        &original,
        &format!(
            "<saml:AudienceRestriction><saml:Audience>{OTHER_AUDIENCE}</saml:Audience></saml:AudienceRestriction>"
        ),
    )?)?;
    match accept(&exchange, &missing) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::AudienceMismatch { expected }) if expected == SP_ENTITY_ID => Ok(()),
            _ => Err(format!("expected AudienceMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected AudienceMismatch".into()),
    }
}

#[test]
fn every_assertion_is_evaluated_when_they_share_issuer_and_principal(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let xml = resigned(&duplicate_assertion(&original, "_second_assertion")?)?;
    let session = accept(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.assertion_id().as_str(),
        assertion_ids(&original)?[0]
    );
    let keys: Vec<_> = session
        .replay_keys()
        .into_iter()
        .map(|key| key.cache_key())
        .collect();
    for id in assertion_ids(&xml)? {
        let key = format!("assertion_id:{id}");
        if !keys.contains(&key) {
            return Err(format!("missing replay key {key}").into());
        }
    }
    Ok(())
}

#[test]
fn a_second_assertion_with_another_issuer_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        IDP_ENTITY_ID,
        "https://other.example/metadata",
    )?)?;
    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::IssuerMismatch { .. }) => Ok(()),
            _ => Err(format!("expected IssuerMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected IssuerMismatch".into()),
    }
}

#[test]
fn a_second_assertion_with_another_principal_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        "alice@example.com",
        "mallory@example.com",
    )?)?;
    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::PrincipalMismatch) => Ok(()),
            _ => Err(format!("expected PrincipalMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected PrincipalMismatch".into()),
    }
}

#[test]
fn one_valid_bearer_confirmation_is_enough() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let at = original.find("</saml:Subject>").ok_or("missing subject")?;
    let mut altered = original;
    altered.insert_str(
        at,
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key\"><saml:SubjectConfirmationData/></saml:SubjectConfirmation>",
    );
    let session = accept(&exchange, &resigned(&altered)?)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn an_additional_assertion_without_bearer_stays_accepted() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        "urn:oasis:names:tc:SAML:2.0:cm:bearer",
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    )?)?;
    let session = accept(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn a_second_bearer_assertion_with_the_wrong_audience_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        SP_ENTITY_ID,
        OTHER_AUDIENCE,
    )?)?;
    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::AudienceMismatch { expected }) if expected == SP_ENTITY_ID => Ok(()),
            _ => Err(format!("expected AudienceMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected AudienceMismatch".into()),
    }
}

#[test]
fn an_unsigned_sibling_assertion_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let stripped = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let key = load_private_key(PRIVKEY, None)?;
    let signed = construct_saml_signature(&stripped, false, &key, CERT, RSA_SHA256, &[], None)?;
    let forged = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_forged\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion>";
    let at = signed.find("<saml:Assertion").ok_or("missing assertion")?;
    let mut attacked = signed;
    attacked.insert_str(at, forged);
    match accept(&exchange, &attacked) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::PotentialWrappingAttack) => Ok(()),
            _ => Err(format!("expected PotentialWrappingAttack, got {error}").into()),
        },
        Ok(session) => Err(format!(
            "trusted {}, including a forged sibling",
            session.name_id().value()
        )
        .into()),
    }
}

#[test]
fn an_unknown_condition_is_rejected_when_its_namespace_is_inherited(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&insert_after_audience_restriction(
        &drop_assertion_namespace_declaration(&response_xml(&exchange.response_fields)?)?,
        "<saml:Condition/>",
    )?)?;
    expect_unrecognized(accept(&exchange, &xml))
}

#[test]
fn the_session_comes_from_the_bearer_assertion() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let duplicated = duplicate_assertion(
        &response_xml(&exchange.response_fields)?,
        "_second_assertion",
    )?;
    let bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    let at = duplicated
        .find(bearer)
        .ok_or("missing bearer confirmation")?;
    let mut altered = duplicated;
    altered.replace_range(
        at..at + bearer.len(),
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    );
    let session = accept(&exchange, &resigned(&altered)?)?;
    assert_eq!(session.assertion_id().as_str(), "_second_assertion");
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn a_later_sha1_assertion_signature_is_rejected_by_the_rsa_sha2_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::constants::signature_algorithm::{RSA_SHA1, RSA_SHA256};
    use saml_rs::XmlSignatureProfile;

    let mut policy = SpValidationPolicy::recommended();
    policy.xml_signatures = XmlSignatureProfile::StrictRsaSha2;
    let exchange = exchange_for(policy, false)?;
    let duplicated = duplicate_assertion(
        &strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?,
        "_second_assertion",
    )?;
    let sha1_on_first = sign_first_assertion(&duplicated, RSA_SHA1)?;
    let unsigned_first = move_last_assertion_first(&sha1_on_first)?;
    let signed = sign_first_assertion(&unsigned_first, RSA_SHA256)?;
    match accept(&exchange, &signed) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::AlgorithmUnsupported) => Ok(()),
            _ => Err(format!("expected AlgorithmUnsupported, got {error}").into()),
        },
        Ok(_) => Err("expected AlgorithmUnsupported".into()),
    }
}

#[test]
fn accept_unsolicited_sso_rejects_a_different_principal() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = exchange_for(SpValidationPolicy::recommended(), true)?;
    let xml = resigned(&replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        "alice@example.com",
        "mallory@example.com",
    )?)?;
    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::PrincipalMismatch) => Ok(()),
            _ => Err(format!("expected PrincipalMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected PrincipalMismatch".into()),
    }
}

#[test]
fn an_omitted_name_id_format_matches_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let duplicated = duplicate_assertion(
        &response_xml(&exchange.response_fields)?,
        "_second_assertion",
    )?;
    let xml = resigned(&set_name_id_format(
        &set_name_id_format(&duplicated, 0, Some(UNSPECIFIED))?,
        1,
        None,
    )?)?;
    let session = accept(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn a_different_name_id_format_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let xml = resigned(&set_name_id_format(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        1,
        Some(PERSISTENT),
    )?)?;
    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::PrincipalMismatch) => Ok(()),
            _ => Err(format!("expected PrincipalMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected PrincipalMismatch".into()),
    }
}

#[test]
fn replay_stores_every_assertion_identifier() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::recommended(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let xml = resigned(&duplicate_assertion(&original, "_second_assertion")?)?;
    let mut cache = MemoryReplayCache::default();
    accept_with(
        &exchange,
        &xml,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache)),
    )?;
    if !cache.seen.contains_key("assertion_id:_second_assertion") {
        return Err("second assertion identifier was not stored".into());
    }

    let reused = resigned(&replace_element_id(
        &replace_element_id(&original, "<saml:Assertion", "_second_assertion")?,
        "<samlp:Response",
        "_other_response",
    )?)?;
    match accept_with(
        &exchange,
        &reused,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache)),
    ) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::ReplayDetected { key }) if key == "assertion_id:_second_assertion" => {
                Ok(())
            }
            _ => Err(format!("expected ReplayDetected, got {error}").into()),
        },
        Ok(_) => Err("expected ReplayDetected".into()),
    }
}

#[test]
fn several_assertions_are_accepted_over_simple_sign() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_simple_sign()?;
    let xml = duplicate_assertion(
        &response_xml(&exchange.response_fields)?,
        "_second_assertion",
    )?;
    let session = accept_simple_sign(&exchange, &xml)?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_ne!(session.assertion_id().as_str(), "_second_assertion");
    Ok(())
}
