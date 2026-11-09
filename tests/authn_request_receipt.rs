//! Identity-provider receipt of `ForceAuthn`, `Is passive`, and `Subject`.
//!
//! SAML Core §3.4.1. These fields are exposed to the identity provider
//! application. Their presence does not reject the request.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, ForceAuthn,
    FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, IsPassive, MetadataTrustPolicy,
    NameId, NameIdFormat, Outbound, PrivateKeyPem, Received, ReplayPolicy, RequestedSubject,
    RequestedSubjectIdentifier, RespondSso, Saml, SamlError, SamlValidationContext, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

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

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )
}

fn idp(validation_policy: IdpValidationPolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(validation_policy)
            .build()?,
    )
}

struct Receipt {
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    received: Received<AuthnRequest>,
}

fn receive(
    validation_policy: IdpValidationPolicy,
    start: StartSso,
    edit: impl FnOnce(String) -> Result<String, Box<dyn std::error::Error>>,
) -> Result<Receipt, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp(validation_policy)?;
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
    let started = sp.start_sso(&idp_descriptor, start)?;
    let xml = edit(authn_request_xml(&started.outbound)?)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(xml.as_bytes()),
        )]),
        validation(),
    )?;
    Ok(Receipt {
        idp,
        sp_descriptor,
        received,
    })
}

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Post => Ok(String::from_utf8(base64_decode(
            &outbound.raw_context().context,
        )?)?),
        Binding::Redirect | Binding::SimpleSign | Binding::Artifact | Binding::Soap => {
            Err("expected an HTTP-POST AuthnRequest".into())
        }
    }
}

fn insert_root_attribute(
    xml: String,
    name: &str,
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let needle = "<samlp:AuthnRequest ";
    let position = xml.find(needle).ok_or("missing AuthnRequest start tag")?;
    let insert_at = position + needle.len();
    Ok(format!(
        "{}{name}=\"{value}\" {}",
        &xml[..insert_at],
        &xml[insert_at..]
    ))
}

fn insert_before_name_id_policy(
    xml: String,
    element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let needle = "<samlp:NameIDPolicy";
    let position = xml.find(needle).ok_or("missing NameIDPolicy")?;
    Ok(format!("{}{element}{}", &xml[..position], &xml[position..]))
}

#[test]
fn received_authn_request_exposes_force_authn_when_set_and_leaves_it_absent_when_omitted(
) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = receive(IdpValidationPolicy::recommended(), StartSso::post(), Ok)?;
    assert_eq!(omitted.received.message().force_authn(), None);

    let required = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post().force_authn(ForceAuthn::Required),
        Ok,
    )?;
    assert_eq!(
        required.received.message().force_authn(),
        Some(ForceAuthn::Required)
    );

    let not_required = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post().force_authn(ForceAuthn::NotRequired),
        Ok,
    )?;
    assert_eq!(
        not_required.received.message().force_authn(),
        Some(ForceAuthn::NotRequired)
    );

    let numeric_true = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "ForceAuthn", "1"),
    )?;
    assert_eq!(
        numeric_true.received.message().force_authn(),
        Some(ForceAuthn::Required)
    );

    let numeric_false = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "ForceAuthn", "0"),
    )?;
    assert_eq!(
        numeric_false.received.message().force_authn(),
        Some(ForceAuthn::NotRequired)
    );
    Ok(())
}

#[test]
fn received_authn_request_exposes_is_passive_when_set_and_leaves_it_absent_when_omitted(
) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = receive(IdpValidationPolicy::recommended(), StartSso::post(), Ok)?;
    assert_eq!(omitted.received.message().is_passive(), None);

    let required = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "IsPassive", "true"),
    )?;
    assert_eq!(
        required.received.message().is_passive(),
        Some(IsPassive::Required)
    );

    let not_required = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "IsPassive", "false"),
    )?;
    assert_eq!(
        not_required.received.message().is_passive(),
        Some(IsPassive::NotRequired)
    );

    let numeric = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "IsPassive", "0"),
    )?;
    assert_eq!(
        numeric.received.message().is_passive(),
        Some(IsPassive::NotRequired)
    );
    Ok(())
}

#[test]
fn received_authn_request_exposes_requested_name_id_and_confirmation(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                concat!(
                "<saml:Subject>",
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" ",
                "NameQualifier=\"https://idp.example.com\" ",
                "SPNameQualifier=\"https://sp.example.com/metadata\" ",
                "SPProvidedID=\"provided-alice\">alice@example.com</saml:NameID>",
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>",
                "</saml:Subject>"
            ),
            )
        },
    )?;
    let subject = receipt
        .received
        .message()
        .requested_subject()
        .ok_or("missing requested subject")?;
    let RequestedSubjectIdentifier::NameId(name_id) = subject.identifier() else {
        return Err("expected a NameID identifier".into());
    };
    assert_eq!(name_id.value(), "alice@example.com");
    assert_eq!(name_id.format(), Some(&NameIdFormat::EmailAddress));
    assert_eq!(
        name_id.format().map(NameIdFormat::as_uri),
        Some(EMAIL_FORMAT)
    );
    assert_eq!(name_id.name_qualifier(), Some("https://idp.example.com"));
    assert_eq!(
        name_id.sp_name_qualifier(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(name_id.sp_provided_id(), Some("provided-alice"));
    assert_eq!(
        subject.name_id().map(NameId::value),
        Some("alice@example.com")
    );
    let confirmation = subject
        .confirmations()
        .first()
        .ok_or("missing confirmation")?;
    assert!(confirmation.raw_xml().contains(BEARER));
    Ok(())
}

#[test]
fn received_authn_request_without_subject_leaves_it_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::recommended(), StartSso::post(), Ok)?;
    assert_eq!(receipt.received.message().requested_subject(), None);
    Ok(())
}

#[test]
fn received_authn_request_without_identifier_presumes_the_presenter(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/></saml:Subject>",
        )
        },
    )?;
    let subject = receipt
        .received
        .message()
        .requested_subject()
        .ok_or("missing requested subject")?;
    assert!(matches!(
        subject.identifier(),
        RequestedSubjectIdentifier::NoIdentifier
    ));
    assert_eq!(subject.name_id(), None);
    assert_eq!(subject.confirmations().len(), 1);
    Ok(())
}

#[test]
fn received_authn_request_keeps_base_id_and_encrypted_id_distinct_from_the_presenter(
) -> Result<(), Box<dyn std::error::Error>> {
    let base_id = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                "<saml:Subject><saml:BaseID>opaque</saml:BaseID></saml:Subject>",
            )
        },
    )?;
    assert!(matches!(
        base_id
            .received
            .message()
            .requested_subject()
            .map(RequestedSubject::identifier),
        Some(RequestedSubjectIdentifier::BaseId)
    ));

    let encrypted = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:EncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID></saml:Subject>",
        )
        },
    )?;
    assert!(matches!(
        encrypted
            .received
            .message()
            .requested_subject()
            .map(RequestedSubject::identifier),
        Some(RequestedSubjectIdentifier::EncryptedId)
    ));
    Ok(())
}

#[test]
fn received_authn_request_accepts_these_fields_under_recommended_and_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    for validation_policy in [
        IdpValidationPolicy::recommended(),
        IdpValidationPolicy::compatibility(),
    ] {
        let receipt = receive(validation_policy, StartSso::post(), |xml| {
            let xml = insert_root_attribute(xml, "ForceAuthn", "true")?;
            let xml = insert_root_attribute(xml, "IsPassive", "true")?;
            insert_before_name_id_policy(
                xml,
                "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
            )
        })?;
        let message = receipt.received.message();
        assert_eq!(message.force_authn(), Some(ForceAuthn::Required));
        assert_eq!(message.is_passive(), Some(IsPassive::Required));
        assert_eq!(
            message
                .requested_subject()
                .and_then(RequestedSubject::name_id)
                .map(NameId::value),
            Some("alice@example.com")
        );

        let response = receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            Subject::new(NameId::new("alice@example.com", None), Vec::new()),
            RespondSso::post(),
        )?;
        assert_eq!(response.raw_context().request_type, "SAMLResponse");
    }
    Ok(())
}

#[test]
fn received_authn_request_rejects_a_non_boolean_force_authn_or_is_passive(
) -> Result<(), Box<dyn std::error::Error>> {
    let force_authn = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "ForceAuthn", "maybe"),
    );
    assert!(matches!(force_authn, Err(error) if error.to_string().contains("ForceAuthn")));

    let is_passive = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| insert_root_attribute(xml, "IsPassive", "TRUE"),
    );
    assert!(matches!(is_passive, Err(error) if error.to_string().contains("IsPassive")));
    Ok(())
}

#[test]
fn received_authn_request_rejects_two_identifiers_or_two_subjects(
) -> Result<(), Box<dyn std::error::Error>> {
    let two_identifiers = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:EncryptedID/></saml:Subject>",
        )
        },
    );
    assert!(matches!(
        two_identifiers,
        Err(error) if error.to_string().contains("one identifier")
    ));

    let two_subjects = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                concat!(
                    "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
                    "<saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject>"
                ),
            )
        },
    );
    assert!(matches!(
        two_subjects,
        Err(error) if error.to_string().contains("Subject must occur once")
    ));
    Ok(())
}

#[test]
fn received_authn_request_rejects_qualified_name_id_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    for attribute in ["NameQualifier", "SPNameQualifier", "SPProvidedID"] {
        let prefixed_only = receive(
            IdpValidationPolicy::recommended(),
            StartSso::post(),
            |xml| {
                insert_before_name_id_policy(
                    xml,
                    &format!(
                        "<saml:Subject><saml:NameID xmlns:x=\"urn:example:foreign\" x:{attribute}=\"https://evil.example\">alice@example.com</saml:NameID></saml:Subject>"
                    ),
                )
            },
        );
        let Err(error) = prefixed_only else {
            return Err(format!("qualified {attribute} was accepted").into());
        };
        let message = error.to_string();
        if !message.contains(attribute) || !message.contains("unqualified") {
            return Err(format!("qualified {attribute} produced {message}").into());
        }
    }

    let both_forms = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                concat!(
                    "<saml:Subject><saml:NameID xmlns:x=\"urn:example:foreign\" ",
                    "NameQualifier=\"https://idp.example.com\" ",
                    "x:NameQualifier=\"https://evil.example\">alice@example.com</saml:NameID></saml:Subject>"
                ),
            )
        },
    );
    assert!(matches!(
        both_forms,
        Err(error) if error.to_string().contains("NameQualifier")
            && error.to_string().contains("unqualified")
    ));
    Ok(())
}

#[test]
fn received_authn_request_rejects_a_qualified_flag_and_a_foreign_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    let qualified = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            let needle = "<samlp:AuthnRequest ";
            let position = xml.find(needle).ok_or("missing AuthnRequest start tag")?;
            let insert_at = position + needle.len();
            Ok(format!(
                "{}xmlns:x=\"urn:example:foreign\" x:ForceAuthn=\"true\" {}",
                &xml[..insert_at],
                &xml[insert_at..]
            ))
        },
    );
    assert!(matches!(
        qualified,
        Err(error) if error.to_string().contains("ForceAuthn")
            && error.to_string().contains("unqualified")
    ));

    let foreign_subject = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                "<x:Subject xmlns:x=\"urn:example:foreign\"><x:NameID>alice@example.com</x:NameID></x:Subject>",
            )
        },
    );
    assert!(matches!(
        foreign_subject,
        Err(error) if error.to_string().contains("Subject")
            && error.to_string().contains("namespace")
    ));

    let foreign_identifier = receive(
        IdpValidationPolicy::recommended(),
        StartSso::post(),
        |xml| {
            insert_before_name_id_policy(
                xml,
                "<saml:Subject><x:EncryptedID xmlns:x=\"urn:example:foreign\"/></saml:Subject>",
            )
        },
    );
    assert!(matches!(
        foreign_identifier,
        Err(error) if error.to_string().contains("EncryptedID")
            && error.to_string().contains("namespace")
    ));
    Ok(())
}
