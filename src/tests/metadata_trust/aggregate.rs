use super::{idp_metadata_xml, sign_metadata_root, sign_root_metadata, trust, CERT};
use saml_rs::{
    CertificatePem, EndpointUrl, EntityId, MetadataAggregate, MetadataTrustPolicy, ResourceLimit,
    RootValidUntilReason, SamlError, SsoRequestBinding, SsoResponseBinding, TimeWindowField,
    XmlLimits,
};
use std::time::{Duration, UNIX_EPOCH};

const FEDERATION: &str = include_str!("../../../tests/fixtures/metadata/federation-aggregate.xml");
const IDP: &str = "https://idp.example.com/metadata";
const SP: &str = "https://sp.example.com/metadata";
const IDP_GROUP_EXPIRY: u64 = 1_893_456_000;
const FEDERATION_EXPIRY: u64 = 1_924_992_000;

#[test]
fn signed_federation_import_selects_named_idp_and_sp() -> Result<(), Box<dyn std::error::Error>> {
    let xml = sign_metadata_root(FEDERATION, &[])?;
    let aggregate = MetadataAggregate::from_xml(
        &xml,
        trust(&[CertificatePem::new(CERT)]),
        XmlLimits::default(),
    )?;
    let idp = aggregate.idp_descriptor(&EntityId::try_new(IDP)?)?;
    let sp = aggregate.sp_descriptor(&EntityId::try_new(SP)?)?;
    drop(aggregate);

    assert_eq!(idp.entity_id().as_str(), IDP);
    assert_eq!(
        idp.single_sign_on_location(SsoRequestBinding::Post)?,
        Some(EndpointUrl::try_new("https://idp.example.com/sso")?)
    );
    assert_eq!(sp.entity_id().as_str(), SP);
    assert_eq!(
        sp.assertion_consumer_location(SsoResponseBinding::Post)?,
        Some(EndpointUrl::try_new("https://sp.example.com/acs")?)
    );
    assert_eq!(
        idp.entity_attributes()?.assurance_certifications(),
        ["https://refeds.org/sirtfi"]
    );
    assert!(sp
        .entity_attributes()?
        .assurance_certifications()
        .is_empty());
    assert_eq!(idp.metadata_xml(), xml);
    assert_eq!(sp.metadata_xml(), xml);
    assert_eq!(idp.signed_metadata_xml(), Some(xml.trim()));
    assert_eq!(sp.signed_metadata_xml(), idp.signed_metadata_xml());

    let nested_expiry = UNIX_EPOCH + Duration::from_secs(IDP_GROUP_EXPIRY);
    idp.ensure_valid_at(nested_expiry - Duration::from_secs(1))?;
    assert!(matches!(
        idp.ensure_valid_at(nested_expiry),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    ));
    let root_expiry = UNIX_EPOCH + Duration::from_secs(FEDERATION_EXPIRY);
    sp.ensure_valid_at(root_expiry - Duration::from_secs(1))?;
    assert!(matches!(
        sp.ensure_valid_at(root_expiry),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    ));
    Ok(())
}

const MAX_VALIDITY: Duration = Duration::from_secs(28 * 86_400);
const ROOT_VALID_UNTIL: &str = r#" validUntil="2031-01-01T00:00:00Z""#;

fn unverified_aggregate(xml: &str) -> Result<MetadataAggregate, SamlError> {
    MetadataAggregate::from_xml(xml, MetadataTrustPolicy::Unverified, XmlLimits::default())
}

fn root_refused<T>(result: Result<T, SamlError>) -> Option<RootValidUntilReason> {
    match result {
        Err(SamlError::MetadataRootValidUntilRefused { reason }) => Some(reason),
        _ => None,
    }
}

#[test]
fn federation_root_valid_until_is_bounded_by_the_max_validity(
) -> Result<(), Box<dyn std::error::Error>> {
    let earliest_accepted = UNIX_EPOCH + Duration::from_secs(FEDERATION_EXPIRY) - MAX_VALIDITY;
    let aggregate = unverified_aggregate(FEDERATION)?
        .require_root_valid_until(earliest_accepted, MAX_VALIDITY)?;
    aggregate
        .idp_descriptor(&EntityId::try_new(IDP)?)?
        .require_root_valid_until(earliest_accepted, MAX_VALIDITY)?;

    let too_early = earliest_accepted - Duration::from_secs(1);
    assert_eq!(
        root_refused(
            unverified_aggregate(FEDERATION)?.require_root_valid_until(too_early, MAX_VALIDITY)
        ),
        Some(RootValidUntilReason::BeyondMaxValidity)
    );

    let nested_expiry = UNIX_EPOCH + Duration::from_secs(IDP_GROUP_EXPIRY);
    let idp = aggregate.idp_descriptor(&EntityId::try_new(IDP)?)?;
    idp.ensure_valid_at(nested_expiry - Duration::from_secs(86_400))?;
    assert_eq!(
        root_refused(
            idp.require_root_valid_until(nested_expiry - Duration::from_secs(86_400), MAX_VALIDITY)
        ),
        Some(RootValidUntilReason::BeyondMaxValidity)
    );
    Ok(())
}

#[test]
fn federation_root_without_valid_until_is_refused_despite_inner_bounds(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = FEDERATION.replace(ROOT_VALID_UNTIL, "");
    let now = UNIX_EPOCH + Duration::from_secs(IDP_GROUP_EXPIRY - 86_400);
    let aggregate = unverified_aggregate(&xml)?;
    let idp = aggregate.idp_descriptor(&EntityId::try_new(IDP)?)?;
    idp.ensure_valid_at(now)?;

    assert_eq!(
        root_refused(idp.require_root_valid_until(now, MAX_VALIDITY)),
        Some(RootValidUntilReason::Missing)
    );
    assert_eq!(
        root_refused(aggregate.require_root_valid_until(now, MAX_VALIDITY)),
        Some(RootValidUntilReason::Missing)
    );
    Ok(())
}

#[test]
fn federation_root_with_malformed_valid_until_is_refused_by_the_requirement(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = FEDERATION.replace(ROOT_VALID_UNTIL, r#" validUntil="soon""#);
    let now = UNIX_EPOCH + Duration::from_secs(IDP_GROUP_EXPIRY - 86_400);

    assert!(matches!(
        unverified_aggregate(&xml)?.require_root_valid_until(now, MAX_VALIDITY),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    ));
    Ok(())
}

#[test]
fn federation_import_requires_a_root_signature_when_pinned(
) -> Result<(), Box<dyn std::error::Error>> {
    let certificates = [CertificatePem::new(CERT)];
    let limits = XmlLimits::default();
    assert!(matches!(
        MetadataAggregate::from_xml(FEDERATION, trust(&certificates), limits),
        Err(SamlError::SignatureVerification { .. })
    ));
    let signed_member = sign_root_metadata(idp_metadata_xml())?;
    let child_signed_only = FEDERATION.replace(
        "</md:EntitiesDescriptor>\n    <md:EntityDescriptor entityID=\"https://sp.example.com/metadata\">",
        &format!(
            "</md:EntitiesDescriptor>{signed_member}<md:EntityDescriptor entityID=\"{SP}\">"
        ),
    );
    assert!(matches!(
        MetadataAggregate::from_xml(&child_signed_only, trust(&certificates), limits),
        Err(SamlError::SignedReferenceMismatch)
    ));
    Ok(())
}

#[test]
fn signed_federation_import_honors_raised_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut limits = XmlLimits::default();
    let end = "</md:EntitiesDescriptor>";
    let mut xml = FEDERATION
        .trim_end()
        .strip_suffix(end)
        .ok_or("missing group end")?
        .to_owned();
    let mut index = 0;
    while xml.len() + 512 < limits.max_bytes {
        xml.push_str(&format!(
            r#"<md:EntityDescriptor entityID="https://member-{index}.example.com/metadata"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://member-{index}.example.com/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>"#
        ));
        index += 1;
    }
    xml.push_str(end);
    let signed = sign_metadata_root(&xml, &[])?;
    let certificates = [CertificatePem::new(CERT)];
    assert!(matches!(
        MetadataAggregate::from_xml(&signed, trust(&certificates), limits),
        Err(SamlError::LimitExceeded {
            limit: ResourceLimit::XmlBytes,
            ..
        })
    ));
    limits.max_bytes = signed.len();
    let aggregate = MetadataAggregate::from_xml(&signed, trust(&certificates), limits)?;
    let sp = aggregate.sp_descriptor(&EntityId::try_new(format!(
        "https://member-{}.example.com/metadata",
        index - 1
    ))?)?;
    assert_eq!(
        sp.assertion_consumer_location(SsoResponseBinding::Post)?,
        Some(EndpointUrl::try_new(format!(
            "https://member-{}.example.com/acs",
            index - 1
        ))?)
    );
    Ok(())
}
