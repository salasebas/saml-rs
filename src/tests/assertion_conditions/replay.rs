use super::*;
use saml_rs::{ClockSkew, XmlPolicy};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[test]
fn replay_honors_the_configured_xml_limits() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_simple_sign(SpValidationPolicy::default())?;
    let mut policy = XmlPolicy::default();
    policy.limits.max_attribute_value_bytes += 1;
    let extension = "x".repeat(policy.limits.max_attribute_value_bytes);
    let xml = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?.replace(
        "</saml:Subject>",
        &format!(
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData xmlns:ext="urn:example:extension" ext:value="{extension}" Recipient="{SP_ACS_SIMPLE}" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>"#
        ),
    );
    let fields = simple_sign_fields(&exchange.response_fields, &xml)?;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::simple_sign(SP_ACS_SIMPLE)?.with_default(),
        )
        .xml(policy)
        .build()?,
    );
    let mut cache = RecordingReplayCache::default();
    let session = sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        Inbound::simple_sign(fields),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(ClockSkew::strict()),
    )?;
    let key = ReplayKey::Assertion(session.assertion_id().clone()).cache_key();
    assert_eq!(
        cache.seen.get(&key),
        Some(&SystemTime::from(OffsetDateTime::parse(
            "2099-01-01T00:00:00Z",
            &Rfc3339
        )?))
    );
    Ok(())
}
