#![cfg(crypto)]

mod common;

use std::time::SystemTime;

use common::signing_credentials;
use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{construct_saml_signature, keys::load_private_key};
use saml_rs::raw::Binding;
use saml_rs::xml::dom::parse;
use saml_rs::{
    AcsEndpoint, AuthnContextComparison, AuthnContextReference, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, BrowserInput, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, IsPassive, MetadataTrustPolicy, NameId,
    Outbound, ReplayPolicy, RequestedAuthnContext, RespondSso, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse,
    StartSso, Subject,
};

const SP: &str = "https://sp.example.com";
const IDP: &str = "https://idp.example.com";
const ACS: &str = "https://sp.example.com/acs";
const SSO: &str = "https://idp.example.com/sso";
const MFA: &str = "https://refeds.org/profile/mfa";
const DECLARATION: &str = "https://idp.example.com/context/token?a=1&b=2";
const PROVIDER: &str = "Accounts & \"Services\" <Portal>";
const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

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
        SpConfig::builder(EntityId::try_new(SP)?)
            .acs_endpoint(AcsEndpoint::post(ACS)?.mark_default())
            .credentials(credentials)
            .validation(SpValidationPolicy {
                authn_requests: AuthnRequestSigningPolicy::Sign,
                ..SpValidationPolicy::recommended()
            })
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP)?)
            .sso_endpoint(SsoEndpoint::redirect(SSO)?)
            .sso_endpoint(SsoEndpoint::post(SSO)?)
            .sso_endpoint(SsoEndpoint::simple_sign(SSO)?)
            .credentials(signing_credentials())
            .validation(IdpValidationPolicy {
                authn_requests: AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::recommended()
            })
            .xml(xml)
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(NameId::new("alice", None), Vec::new())
}

fn request_xml(outbound: &Outbound<AuthnRequest>) -> Result<String, Box<dyn std::error::Error>> {
    let context = outbound.raw_context();
    let bytes = match context.binding {
        Binding::Redirect => {
            let url = url::Url::parse(&context.context)?;
            let value = url
                .query_pairs()
                .find(|(name, _)| name == "SAMLRequest")
                .ok_or("missing request")?
                .1;
            deflate_raw_decode(&base64_decode(&value)?)?
        }
        Binding::Post | Binding::SimpleSign => base64_decode(&context.context)?,
        Binding::Artifact | Binding::Soap => return Err("unexpected request binding".into()),
    };
    Ok(String::from_utf8(bytes)?)
}

fn request_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<BrowserInput<AuthnRequest>, SamlError> {
    match outbound.raw_context().binding {
        Binding::Redirect => Ok(BrowserInput::<AuthnRequest>::redirect(
            outbound
                .redirect_url()?
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("missing query".into()))?
                .1,
        )),
        Binding::Post => Ok(BrowserInput::<AuthnRequest>::post(
            outbound.post_form()?.fields().to_vec(),
        )),
        Binding::SimpleSign => Ok(BrowserInput::<AuthnRequest>::simple_sign(
            outbound.post_form()?.fields().to_vec(),
        )),
        Binding::Artifact | Binding::Soap => Err(SamlError::UndefinedBinding),
    }
}

fn response_input(
    outbound: &Outbound<SsoResponse>,
) -> Result<BrowserInput<SsoResponse>, SamlError> {
    Ok(BrowserInput::<SsoResponse>::post(
        outbound.post_form()?.fields().to_vec(),
    ))
}

#[test]
fn requested_context_rejects_empty_and_mixed_references() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(matches!(
        RequestedAuthnContext::new(AuthnContextComparison::Exact, Vec::new()),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        RequestedAuthnContext::new(
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
                    let requested = RequestedAuthnContext::new(comparison, references.clone())?;
                    let started = sp.start_sso(
                        &idp_descriptor,
                        start
                            .clone()
                            .requested_authn_context(requested.clone())
                            .is_passive(passive)
                            .provider_name(PROVIDER),
                    )?;
                    let xml = request_xml(&started.outbound)?;
                    let document = parse(&xml)?;
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
                    assert_eq!(received.message().is_passive(), Some(passive));
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
            StartSso::post().requested_authn_context(RequestedAuthnContext::new(
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
            subject(),
            RespondSso::post()
                .apply_web_browser_sso_generation_rules()
                .authn_context(reference.clone()),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            response_input(&response)?,
            validation(),
        )?;
        let context = session
            .authn_session()
            .authn_context()
            .ok_or("missing context")?;
        assert_eq!(
            context
                .class_reference()
                .or(context.declaration_reference()),
            Some(&reference)
        );
        assert!(!context.has_declaration());
        assert!(context.authenticating_authorities().is_empty());
        assert!(session.authn_session().subject_locality().is_none());
    }
    Ok(())
}

#[test]
fn unsolicited_sso_exposes_the_asserted_context() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .authn_context(AuthnContextReference::class(MFA)?),
    )?;
    let session =
        sp.accept_unsolicited_sso(&idp_descriptor, response_input(&response)?, validation())?;
    assert_eq!(
        session
            .authn_session()
            .authn_context()
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
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .sign_response(),
    )?;
    let xml = String::from_utf8(base64_decode(&response.raw_context().context)?)?;
    let document = parse(&xml)?;
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
    let document = parse(&edited)?;
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
    let signed = construct_saml_signature(
        &unsigned,
        true,
        &load_private_key(KEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(vec![FormField::new(
            "SAMLResponse",
            base64_encode(signed.as_bytes()),
        )]),
        validation(),
    )?;
    let sessions = session.authn_sessions();
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
    let credentials = saml_rs::Credentials {
        encryption_certificate: Some(saml_rs::CertificatePem::new(CERT)),
        decryption_key: Some(saml_rs::PrivateKeyPem::new(KEY)),
        ..signing_credentials()
    };
    let (sp, idp, sp_descriptor, idp_descriptor) = parties_with(
        saml_rs::XmlPolicy {
            encryption: saml_rs::XmlEncryptionPolicy::encrypt_assertions(),
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
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .authn_context(AuthnContextReference::class(MFA)?),
    )?;
    let xml = String::from_utf8(base64_decode(&response.raw_context().context)?)?;
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
            .authn_session()
            .authn_context()
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
        SpConfig::builder(EntityId::try_new(SP)?)
            .acs_endpoint(AcsEndpoint::post(ACS)?.mark_default())
            .credentials(signing_credentials())
            .validation(SpValidationPolicy {
                authn_requests: AuthnRequestSigningPolicy::Sign,
                ..SpValidationPolicy::recommended()
            })
            .templates(saml_rs::TemplatePolicy {
                login_request_template: Some(saml_rs::template::LOGIN_REQUEST_TEMPLATE.into()),
                ..Default::default()
            })
            .build()?,
    )?;
    sp.start_sso(&idp_descriptor, StartSso::post())?;
    for start in [
        StartSso::post().is_passive(IsPassive::Required),
        StartSso::post().provider_name(PROVIDER),
        StartSso::post().requested_authn_context(RequestedAuthnContext::new(
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
            start.requested_authn_context(RequestedAuthnContext::new(
                AuthnContextComparison::Exact,
                vec![AuthnContextReference::class(MFA)?],
            )?),
        )?;
        let xml = request_xml(&started.outbound)?.replace(MFA, "urn:example:weaker");
        let context = started.outbound.raw_context();
        let input = match context.binding {
            Binding::Redirect => {
                let original = url::Url::parse(started.outbound.redirect_url()?)?;
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
                BrowserInput::<AuthnRequest>::redirect(redirected.query().ok_or("missing query")?)
            }
            Binding::Post | Binding::SimpleSign => {
                let fields = started
                    .outbound
                    .post_form()?
                    .fields()
                    .iter()
                    .map(|field| {
                        if field.name() == "SAMLRequest" {
                            FormField::new("SAMLRequest", base64_encode(xml.as_bytes()))
                        } else {
                            field.clone()
                        }
                    })
                    .collect();
                if context.binding == Binding::Post {
                    BrowserInput::<AuthnRequest>::post(fields)
                } else {
                    BrowserInput::<AuthnRequest>::simple_sign(fields)
                }
            }
            Binding::Artifact | Binding::Soap => return Err("unexpected request binding".into()),
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
        StartSso::post().requested_authn_context(RequestedAuthnContext::new(
            AuthnContextComparison::Exact,
            vec![AuthnContextReference::class(MFA)?],
        )?),
    )?;
    let xml = request_xml(&started.outbound)?.replace(MFA, "relative-context");
    let document = parse(&xml)?;
    let signature = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "Signature")
        .ok_or("missing request signature")?;
    let unsigned = format!("{}{}", &xml[..signature.start], &xml[signature.end..]);
    let signed = construct_saml_signature(
        &unsigned,
        true,
        &load_private_key(KEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(signed.as_bytes()),
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
