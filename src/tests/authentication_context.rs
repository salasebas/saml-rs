#![cfg(crypto)]

use super::common;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::signing_credentials;
use saml_rs::binding::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::xml::dom::parse_document;
use saml_rs::{
    AcsEndpoint, AuthnContextComparison, AuthnContextReference, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, EntityId, FormField, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, IsPassive, MetadataTrustPolicy, NameId, Outbound,
    OutboundDelivery, ReplayPolicy, RequestedAuthnContext, RespondSso, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint,
    SsoResponse, StartSso,
};

const SP: &str = "https://sp.example.com";
const IDP: &str = "https://idp.example.com";
const ACS: &str = "https://sp.example.com/acs";
const SSO: &str = "https://idp.example.com/sso";
const MFA: &str = "https://refeds.org/profile/mfa";
const DECLARATION: &str = "https://idp.example.com/context/token?a=1&b=2";
const PROVIDER: &str = "Accounts & \"Services\" <Portal>";
const KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

type Parties = (
    Saml<saml_rs::Sp>,
    Saml<saml_rs::Idp>,
    SpDescriptor,
    IdpDescriptor,
);

fn parties() -> Result<Parties, SamlError> {
    parties_with(saml_rs::XmlPolicy::default(), signing_credentials())
}

fn parties_with(
    xml: saml_rs::XmlPolicy,
    credentials: saml_rs::Credentials,
) -> Result<Parties, SamlError> {
    let sp = Saml::sp(
        SpConfig::builder(
            EntityId::try_new(SP)?,
            AcsEndpoint::post(ACS)?.with_default(),
        )
        .credentials(credentials)
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .build()?,
    );
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP)?, SsoEndpoint::redirect(SSO)?)
            .sso_endpoint(SsoEndpoint::post(SSO)?)
            .sso_endpoint(SsoEndpoint::simple_sign(SSO)?)
            .credentials(signing_credentials())
            .validation(IdpValidationPolicy {
                authn_requests: AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::recommended()
            })
            .xml(xml)
            .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn principal() -> NameId {
    NameId::new("alice")
}

fn request_xml(outbound: &Outbound<AuthnRequest>) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = match outbound.delivery() {
        OutboundDelivery::Redirect(url) => {
            let url = url::Url::parse(url)?;
            let value = url
                .query_pairs()
                .find(|(name, _)| name == "SAMLRequest")
                .ok_or("missing request")?
                .1;
            deflate_raw_decode(
                &STANDARD.decode(value.as_bytes())?,
                MAX_DEFLATE_RAW_DECODE_BYTES,
            )?
        }
        OutboundDelivery::PostForm(form) => {
            STANDARD.decode(form.value("SAMLRequest").ok_or("missing request")?)?
        }
        OutboundDelivery::SoapRequest(_) | OutboundDelivery::SoapResponse(_) => {
            return Err("an AuthnRequest is not sent over SOAP".into())
        }
    };
    Ok(String::from_utf8(bytes)?)
}

fn request_input(outbound: &Outbound<AuthnRequest>) -> Result<Inbound<AuthnRequest>, SamlError> {
    match outbound.delivery() {
        OutboundDelivery::Redirect(url) => Ok(Inbound::redirect(
            url.split_once('?')
                .ok_or_else(|| SamlError::Invalid("missing query".into()))?
                .1,
        )),
        OutboundDelivery::PostForm(form) if form.value("SigAlg").is_some() => {
            Ok(Inbound::simple_sign(form.fields().to_vec()))
        }
        OutboundDelivery::PostForm(form) => Ok(Inbound::post(form.fields().to_vec())),
        OutboundDelivery::SoapRequest(_) | OutboundDelivery::SoapResponse(_) => Err(
            SamlError::Invalid("an AuthnRequest is not sent over SOAP".into()),
        ),
    }
}

fn response_input(outbound: &Outbound<SsoResponse>) -> Result<Inbound<SsoResponse>, SamlError> {
    Ok(Inbound::post(outbound.post_form()?.fields().to_vec()))
}

#[test]
fn requested_context_rejects_empty_and_mixed_references() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(matches!(
        RequestedAuthnContext::try_new(AuthnContextComparison::Exact, Vec::new()),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        RequestedAuthnContext::try_new(
            AuthnContextComparison::Exact,
            vec![
                AuthnContextReference::class(MFA)?,
                AuthnContextReference::declaration(DECLARATION)?
            ]
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn signed_requests_round_trip_context_passive_and_provider_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    for start in [
        StartSso::redirect(),
        StartSso::post(),
        StartSso::simple_sign(),
    ] {
        for comparison in [
            AuthnContextComparison::Exact,
            AuthnContextComparison::Minimum,
            AuthnContextComparison::Maximum,
            AuthnContextComparison::Better,
        ] {
            for references in [
                vec![
                    AuthnContextReference::class(MFA)?,
                    AuthnContextReference::unspecified_class(),
                ],
                vec![
                    AuthnContextReference::declaration(DECLARATION)?,
                    AuthnContextReference::declaration("urn:example:fallback")?,
                ],
            ] {
                for passive in [IsPassive::Required, IsPassive::NotRequired] {
                    let requested = RequestedAuthnContext::try_new(comparison, references.clone())?;
                    let started = sp.start_sso(
                        &idp_descriptor,
                        start
                            .clone()
                            .requested_authn_context(requested.clone())
                            .passive(passive)
                            .provider_name(PROVIDER),
                    )?;
                    let xml = request_xml(&started.outbound)?;
                    let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
                    let children: Vec<_> = document
                        .root
                        .children
                        .iter()
                        .filter(|child| child.local_name != "Signature")
                        .map(|child| child.local_name.as_str())
                        .collect();
                    assert_eq!(
                        children,
                        ["Issuer", "NameIDPolicy", "RequestedAuthnContext"]
                    );
                    let received = idp.receive_sso(
                        &sp_descriptor,
                        request_input(&started.outbound)?,
                        validation(),
                    )?;
                    assert_eq!(
                        received.message().requested_authn_context(),
                        Some(&requested)
                    );
                    assert_eq!(received.message().passive(), Some(passive));
                    assert_eq!(received.message().provider_name(), Some(PROVIDER));
                }
            }
        }
        let started = sp.start_sso(&idp_descriptor, start)?;
        let xml = request_xml(&started.outbound)?;
        assert!(!xml.contains("RequestedAuthnContext"));
        assert!(!xml.contains("IsPassive="));
        assert!(!xml.contains("ProviderName="));
    }
    Ok(())
}

#[test]
fn respond_and_finish_sso_preserve_class_and_declaration_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    for reference in [
        AuthnContextReference::class(MFA)?,
        AuthnContextReference::declaration(DECLARATION)?,
    ] {
        let started = sp.start_sso(
            &idp_descriptor,
            StartSso::post().requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                vec![reference.clone()],
            )?),
        )?;
        let received = idp.receive_sso(
            &sp_descriptor,
            request_input(&started.outbound)?,
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal()).with_authn_context(reference.clone()),
            RespondSso::post().apply_producer_rules(),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            response_input(&response)?,
            validation(),
        )?;
        let statement = session
            .authn_statements()
            .first()
            .ok_or("missing AuthnStatement")?;
        let context = statement.authn_context().ok_or("missing context")?;
        assert_eq!(
            context
                .class_reference()
                .or(context.declaration_reference()),
            Some(&reference)
        );
        assert!(!context.has_declaration());
        assert!(context.authenticating_authorities().is_empty());
        assert!(statement.subject_locality().is_none());
    }
    Ok(())
}

#[test]
fn unsolicited_sso_exposes_the_asserted_context() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()).with_authn_context(AuthnContextReference::class(MFA)?),
        RespondSso::post().apply_producer_rules(),
    )?;
    let session =
        sp.accept_unsolicited_sso(&idp_descriptor, response_input(&response)?, validation())?;
    assert_eq!(
        session
            .authn_statements()
            .first()
            .and_then(|statement| statement.authn_context())
            .and_then(|context| context.class_reference())
            .map(AuthnContextReference::uri),
        Some(MFA)
    );
    Ok(())
}

#[test]
fn repeated_statements_keep_their_context_locality_and_session_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post().apply_producer_rules().sign_response(),
    )?;
    let xml = String::from_utf8(STANDARD.decode(&response.raw_context().context)?)?;
    let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
    let assertion = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "Assertion")
        .ok_or("missing assertion")?;
    let statement = assertion
        .children
        .iter()
        .find(|child| child.local_name == "AuthnStatement")
        .ok_or("missing statement")?;
    let instant = statement.attr("AuthnInstant").ok_or("missing instant")?;
    let statements = format!(
        r#"<saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="first"><saml:SubjectLocality Address="192.0.2.1" DNSName="client.example.com"/><saml:AuthnContext><saml:AuthnContextClassRef>  {MFA}  </saml:AuthnContextClassRef><saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef><saml:AuthenticatingAuthority> https://upstream.example.com </saml:AuthenticatingAuthority><saml:AuthenticatingAuthority>urn:example:second</saml:AuthenticatingAuthority><saml:AuthenticatingAuthority>urn:example:second</saml:AuthenticatingAuthority></saml:AuthnContext></saml:AuthnStatement><saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="second"><saml:SubjectLocality/><saml:AuthnContext><saml:AuthnContextDecl><details xmlns="urn:example:declaration"/></saml:AuthnContextDecl></saml:AuthnContext></saml:AuthnStatement><saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="third"><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:third</saml:AuthnContextClassRef><other:AuthnContextDeclRef xmlns:other="urn:other">urn:example:forged</other:AuthnContextDeclRef></saml:AuthnContext></saml:AuthnStatement>"#
    );
    let edited = format!(
        "{}{}{}",
        &xml[..statement.start],
        statements,
        &xml[statement.end..]
    );
    let document = parse_document(&edited, saml_rs::XmlLimits::default())?;
    let selected = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "Assertion")
        .ok_or("missing selected assertion")?;
    let selected_id = selected
        .attr("ID")
        .ok_or("missing assertion ID")?
        .to_string();
    let confirmation = selected
        .children
        .iter()
        .find(|child| child.local_name == "Subject")
        .and_then(|subject| {
            subject
                .children
                .iter()
                .find(|child| child.local_name == "SubjectConfirmation")
        })
        .ok_or("missing bearer confirmation")?;
    let unselected = format!(
        "{}{}",
        &edited[selected.start..confirmation.start],
        &edited[confirmation.end..selected.end],
    )
    .replacen(
        &format!("ID=\"{selected_id}\""),
        "ID=\"_unselected_assertion\"",
        1,
    )
    .replace(MFA, "urn:example:unselected")
    .replace("192.0.2.1", "192.0.2.99");
    let edited = format!(
        "{}{unselected}{}",
        &edited[..selected.start],
        &edited[selected.start..]
    );
    let document = parse_document(&edited, saml_rs::XmlLimits::default())?;
    let mut unsigned = edited.clone();
    let mut signatures: Vec<_> = document
        .root
        .children
        .iter()
        .filter(|child| child.local_name == "Signature")
        .map(|child| (child.start, child.end))
        .collect();
    for assertion in &document.root.children {
        signatures.extend(
            assertion
                .children
                .iter()
                .filter(|child| child.local_name == "Signature")
                .map(|child| (child.start, child.end)),
        );
    }
    signatures.sort_unstable();
    for (start, end) in signatures.into_iter().rev() {
        unsigned.replace_range(start..end, "");
    }
    let signed = sign_saml_xml(
        &unsigned,
        true,
        &read_private_key(KEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(vec![FormField::new(
            "SAMLResponse",
            STANDARD.encode(signed.as_bytes()),
        )]),
        validation(),
    )?;
    let sessions = session.authn_statements();
    assert_eq!(session.assertion_id().as_str(), selected_id);
    assert_eq!(sessions.len(), 3);
    assert_eq!(
        sessions
            .iter()
            .map(|session| session.session_index().map(|index| index.as_str()))
            .collect::<Vec<_>>(),
        [Some("first"), Some("second"), Some("third")]
    );
    let first = sessions[0].authn_context().ok_or("missing first context")?;
    assert_eq!(
        first.class_reference(),
        Some(&AuthnContextReference::class(MFA)?)
    );
    assert_eq!(
        first.declaration_reference(),
        Some(&AuthnContextReference::declaration(
            "urn:example:declaration"
        )?)
    );
    assert!(!first.has_declaration());
    assert_eq!(
        first.authenticating_authorities(),
        [
            "https://upstream.example.com",
            "urn:example:second",
            "urn:example:second"
        ]
    );
    let locality = sessions[0].subject_locality().ok_or("missing locality")?;
    assert_eq!(locality.address(), Some("192.0.2.1"));
    assert_eq!(locality.dns_name(), Some("client.example.com"));
    let second = sessions[1]
        .authn_context()
        .ok_or("missing second context")?;
    assert!(second.class_reference().is_none());
    assert!(second.declaration_reference().is_none());
    assert!(second.has_declaration());
    let locality = sessions[1]
        .subject_locality()
        .ok_or("missing empty locality")?;
    assert!(locality.address().is_none());
    assert!(locality.dns_name().is_none());
    let third = sessions[2].authn_context().ok_or("missing third context")?;
    assert_eq!(
        third.class_reference().map(AuthnContextReference::uri),
        Some("urn:example:third")
    );
    assert!(third.declaration_reference().is_none());
    assert!(sessions[2].subject_locality().is_none());
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn encrypted_assertion_exposes_the_asserted_context() -> Result<(), Box<dyn std::error::Error>> {
    let credentials =
        signing_credentials().with_decryption_credential(saml_rs::X509Credential::new(
            saml_rs::CertificatePem::new(CERT),
            saml_rs::PrivateKeyPem::new(KEY),
        ));
    let (sp, idp, sp_descriptor, idp_descriptor) = parties_with(
        saml_rs::XmlPolicy {
            encryption: saml_rs::XmlEncryptionPolicy {
                assertions: saml_rs::AssertionEncryptionPolicy::EncryptAssertions,
                ..saml_rs::XmlEncryptionPolicy::default()
            },
            ..Default::default()
        },
        credentials,
    )?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()).with_authn_context(AuthnContextReference::class(MFA)?),
        RespondSso::post().apply_producer_rules(),
    )?;
    let xml = String::from_utf8(STANDARD.decode(&response.raw_context().context)?)?;
    assert!(xml.contains("EncryptedAssertion"));
    assert!(!xml.contains(MFA));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        response_input(&response)?,
        validation(),
    )?;
    assert_eq!(
        session
            .authn_statements()
            .first()
            .and_then(|statement| statement.authn_context())
            .and_then(|context| context.class_reference())
            .map(AuthnContextReference::uri),
        Some(MFA)
    );
    Ok(())
}

#[test]
fn typed_request_preferences_require_the_builtin_renderer() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, _, _, idp_descriptor) = parties()?;
    let sp = Saml::sp(
        SpConfig::builder(
            EntityId::try_new(SP)?,
            AcsEndpoint::post(ACS)?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .authn_request_template(saml_rs::config::AUTHN_REQUEST_TEMPLATE)
        .build()?,
    );
    sp.start_sso(&idp_descriptor, StartSso::post())?;
    for start in [
        StartSso::post().passive(IsPassive::Required),
        StartSso::post().provider_name(PROVIDER),
        StartSso::post().requested_authn_context(RequestedAuthnContext::try_new(
            AuthnContextComparison::Exact,
            vec![AuthnContextReference::class(MFA)?],
        )?),
    ] {
        assert!(matches!(
            sp.start_sso(&idp_descriptor, start),
            Err(SamlError::Invalid(_))
        ));
    }
    Ok(())
}

#[test]
fn provider_name_must_be_xml_text_and_may_be_empty() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    assert!(matches!(
        sp.start_sso(
            &idp_descriptor,
            StartSso::post().provider_name("invalid\0name")
        ),
        Err(SamlError::Invalid(_))
    ));
    let started = sp.start_sso(&idp_descriptor, StartSso::post().provider_name(""))?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    assert_eq!(received.message().provider_name(), Some(""));
    Ok(())
}

#[test]
fn request_signature_covers_the_requested_context_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    for start in [
        StartSso::redirect(),
        StartSso::post(),
        StartSso::simple_sign(),
    ] {
        let started = sp.start_sso(
            &idp_descriptor,
            start.requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                vec![AuthnContextReference::class(MFA)?],
            )?),
        )?;
        let xml = request_xml(&started.outbound)?.replace(MFA, "urn:example:weaker");
        let input = match started.outbound.delivery() {
            OutboundDelivery::Redirect(url) => {
                let original = url::Url::parse(url)?;
                let redirected = saml_rs::binding::build_redirect_url(
                    SSO,
                    saml_rs::constants::ParserType::SamlRequest,
                    &xml,
                    None,
                )?;
                let mut redirected = url::Url::parse(&redirected)?;
                for (name, value) in original
                    .query_pairs()
                    .filter(|(name, _)| name == "SigAlg" || name == "Signature")
                {
                    redirected.query_pairs_mut().append_pair(&name, &value);
                }
                Inbound::redirect(redirected.query().ok_or("missing query")?)
            }
            OutboundDelivery::PostForm(form) => {
                let fields = form
                    .fields()
                    .iter()
                    .map(|field| {
                        if field.name() == "SAMLRequest" {
                            FormField::new("SAMLRequest", STANDARD.encode(xml.as_bytes()))
                        } else {
                            field.clone()
                        }
                    })
                    .collect();
                if form.value("SigAlg").is_some() {
                    Inbound::simple_sign(fields)
                } else {
                    Inbound::post(fields)
                }
            }
            OutboundDelivery::SoapRequest(_) | OutboundDelivery::SoapResponse(_) => {
                return Err("an AuthnRequest is not sent over SOAP".into())
            }
        };
        assert!(idp
            .receive_sso(&sp_descriptor, input, validation())
            .is_err());
    }
    Ok(())
}

#[test]
fn a_received_relative_reference_is_exposed_but_cannot_be_sent_again(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().requested_authn_context(RequestedAuthnContext::try_new(
            AuthnContextComparison::Exact,
            vec![AuthnContextReference::class(MFA)?],
        )?),
    )?;
    let xml = request_xml(&started.outbound)?.replace(MFA, "relative-context");
    let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
    let signature = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "Signature")
        .ok_or("missing request signature")?;
    let unsigned = format!("{}{}", &xml[..signature.start], &xml[signature.end..]);
    let signed = sign_saml_xml(
        &unsigned,
        true,
        &read_private_key(KEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(signed.as_bytes()),
        )]),
        validation(),
    )?;
    let requested = received
        .message()
        .requested_authn_context()
        .ok_or("missing context")?;
    assert_eq!(requested.references()[0].uri(), "relative-context");
    assert!(matches!(
        sp.start_sso(
            &idp_descriptor,
            StartSso::post().requested_authn_context(requested.clone())
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}
