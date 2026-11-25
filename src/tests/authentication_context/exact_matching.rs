use super::{
    parties, principal, request_input, resign_response_xml, response_input, validation, ACS,
    DECLARATION, IDP, MFA,
};
use crate::tests::post_validation::post_validation;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::xml::dom::parse_document;
use saml_rs::{
    AuthnContextComparison, AuthnContextReference, FormField, InMemoryReplayCache, Inbound, NameId,
    Outbound, OutstandingLogout, PendingAuthnRequest, PendingAuthnRequestSnapshot, RelayState,
    RequestedAuthnContext, RespondSso, SamlError, SamlInstant, SsoAssertion, SsoOutcome,
    SsoResponse, StartSso, Status, SubordinateStatusCode,
};

const PASSWORD_PROTECTED_TRANSPORT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

fn resign_response_with_statements(
    response: &Outbound<SsoResponse>,
    replacement_statements: &str,
) -> Result<Inbound<SsoResponse>, Box<dyn std::error::Error>> {
    let xml = String::from_utf8(
        STANDARD.decode(
            response
                .post_form()?
                .value("SAMLResponse")
                .ok_or("missing SAMLResponse")?,
        )?,
    )?;
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
    let statements = replacement_statements.replace("{instant}", instant);
    let edited = format!(
        "{}{}{}",
        &xml[..statement.start],
        statements,
        &xml[statement.end..]
    );
    let signed = resign_response_xml(&edited)?;
    Ok(Inbound::post(vec![FormField::new(
        "SAMLResponse",
        STANDARD.encode(signed.as_bytes()),
    )]))
}

#[test]
fn require_exact_authn_context_validates_start_sso_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _, _, idp_descriptor) = parties()?;
    assert!(matches!(
        sp.start_sso(
            &idp_descriptor,
            StartSso::post().require_exact_authn_context()
        ),
        Err(SamlError::Invalid(_))
    ));
    for comparison in [
        AuthnContextComparison::Minimum,
        AuthnContextComparison::Maximum,
        AuthnContextComparison::Better,
    ] {
        let requested =
            RequestedAuthnContext::try_new(comparison, [AuthnContextReference::class(MFA)?])?;
        assert!(matches!(
            sp.start_sso(
                &idp_descriptor,
                StartSso::post()
                    .requested_authn_context(requested)
                    .require_exact_authn_context()
            ),
            Err(SamlError::Invalid(_))
        ));
    }

    let exact = RequestedAuthnContext::try_new(
        AuthnContextComparison::Exact,
        [AuthnContextReference::class(MFA)?],
    )?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect()
            .require_exact_authn_context()
            .requested_authn_context(exact.clone()),
    )?;
    assert_eq!(
        started.pending.required_authn_context(),
        Some(exact.references())
    );

    let without_opt_in = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().requested_authn_context(exact),
    )?;
    assert_eq!(without_opt_in.pending.required_authn_context(), None);
    Ok(())
}

#[test]
fn exact_authn_context_opt_in_accepts_matching_class_and_declaration_across_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let secondary_class =
        AuthnContextReference::class("urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken")?;
    for (requested_refs, achieved) in [
        (
            vec![AuthnContextReference::class(MFA)?, secondary_class.clone()],
            secondary_class,
        ),
        (
            vec![AuthnContextReference::declaration(DECLARATION)?],
            AuthnContextReference::declaration(DECLARATION)?,
        ),
    ] {
        let requested =
            RequestedAuthnContext::try_new(AuthnContextComparison::Exact, requested_refs.clone())?;
        let started = sp.start_sso(
            &idp_descriptor,
            StartSso::post()
                .requested_authn_context(requested)
                .require_exact_authn_context(),
        )?;
        assert_eq!(
            started.pending.required_authn_context(),
            Some(requested_refs.as_slice())
        );
        let restored = PendingAuthnRequest::from_snapshot(started.pending.snapshot())?;
        assert_eq!(restored, started.pending);

        let received = idp.receive_sso(
            &sp_descriptor,
            request_input(&started.outbound)?,
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal(), SystemTime::now()).authn_context(achieved.clone()),
            RespondSso::post(),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &restored,
            response_input(&response)?,
            post_validation(&mut Default::default()),
        )?;
        let context = session
            .authn_statements()
            .first()
            .ok_or("missing AuthnStatement")?
            .authn_context();
        assert_eq!(
            context
                .class_reference()
                .or(context.declaration_reference()),
            Some(&achieved)
        );
    }
    Ok(())
}

#[test]
fn exact_authn_context_opt_in_matches_later_statement_or_declaration_alongside_class(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa),
        RespondSso::post().sign_response(),
    )?;
    let multi_statement = resign_response_with_statements(
        &response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>  {MFA}  </saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        multi_statement,
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.authn_statements().len(), 2);

    let decl = AuthnContextReference::declaration("urn:example:declaration")?;
    let started_decl = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [decl.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received_decl = idp.receive_sso(
        &sp_descriptor,
        request_input(&started_decl.outbound)?,
        validation(),
    )?;
    let response_decl = idp.respond_sso(
        &sp_descriptor,
        &received_decl,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(decl),
        RespondSso::post().sign_response(),
    )?;
    let combined = resign_response_with_statements(
        &response_decl,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef><saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;
    sp.finish_sso(
        &idp_descriptor,
        &started_decl.pending,
        combined,
        post_validation(&mut Default::default()),
    )?;
    Ok(())
}

#[test]
fn exact_authn_context_opt_in_rejects_different_wrong_kind_and_missing_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let restored = PendingAuthnRequest::from_snapshot(started.pending.snapshot())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let base_response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa.clone()),
        RespondSso::post().sign_response(),
    )?;

    let password = AuthnContextReference::class(PASSWORD_PROTECTED_TRANSPORT)?;
    let different = resign_response_with_statements(
        &base_response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;
    let mut replay_cache = InMemoryReplayCache::new();
    match sp.finish_sso(
        &idp_descriptor,
        &restored,
        different.clone(),
        post_validation(&mut replay_cache),
    ) {
        Err(SamlError::AuthnContextMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, vec![mfa.clone()]);
            assert_eq!(actual, vec![password]);
        }
        other => return Err(format!("expected AuthnContextMismatch, got {other:?}").into()),
    }

    let wrong_kind = resign_response_with_statements(
        &base_response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextDeclRef>{MFA}</saml:AuthnContextDeclRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;
    match sp.finish_sso(
        &idp_descriptor,
        &restored,
        wrong_kind,
        post_validation(&mut replay_cache),
    ) {
        Err(SamlError::AuthnContextMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, vec![mfa.clone()]);
            assert_eq!(actual, vec![AuthnContextReference::declaration(MFA)?]);
        }
        other => return Err(format!("expected AuthnContextMismatch, got {other:?}").into()),
    }

    let decl_only = resign_response_with_statements(
        &base_response,
        r#"<saml:AuthnStatement AuthnInstant="{instant}"><saml:AuthnContext><saml:AuthnContextDecl><details xmlns="urn:example:declaration"/></saml:AuthnContextDecl></saml:AuthnContext></saml:AuthnStatement>"#,
    )?;
    match sp.finish_sso(
        &idp_descriptor,
        &restored,
        decl_only,
        post_validation(&mut replay_cache),
    ) {
        Err(SamlError::AuthnContextMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, vec![mfa.clone()]);
            assert!(actual.is_empty());
        }
        other => return Err(format!("expected AuthnContextMismatch, got {other:?}").into()),
    }

    let no_statement = resign_response_with_statements(&base_response, "")?;
    match sp.finish_sso(
        &idp_descriptor,
        &restored,
        no_statement,
        post_validation(&mut replay_cache),
    ) {
        Err(SamlError::AuthnContextMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, vec![mfa]);
            assert!(actual.is_empty());
        }
        other => return Err(format!("expected AuthnContextMismatch, got {other:?}").into()),
    }

    let other_logout = OutstandingLogout::try_new(
        idp_descriptor.entity_id().clone(),
        NameId::new("bob"),
        Vec::new(),
        SamlInstant::try_new("2099-01-01T00:00:00Z")?,
    )?;
    assert!(matches!(
        sp.finish_sso_with_outstanding_logout(
            &idp_descriptor,
            &restored,
            different,
            post_validation(&mut replay_cache),
            &other_logout,
        ),
        Err(SamlError::AuthnContextMismatch { .. })
    ));

    sp.finish_sso(
        &idp_descriptor,
        &restored,
        response_input(&base_response)?,
        post_validation(&mut replay_cache),
    )?;
    Ok(())
}

#[test]
fn matching_outstanding_logout_records_replay_even_when_authn_context_mismatches(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let base_response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa),
        RespondSso::post().sign_response(),
    )?;
    let different = resign_response_with_statements(
        &base_response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;
    let matching_logout = OutstandingLogout::try_new(
        idp_descriptor.entity_id().clone(),
        principal(),
        Vec::new(),
        SamlInstant::try_new("2099-01-01T00:00:00Z")?,
    )?;
    let mut replay_cache = InMemoryReplayCache::new();
    assert!(matches!(
        sp.finish_sso_with_outstanding_logout(
            &idp_descriptor,
            &started.pending,
            different,
            post_validation(&mut replay_cache),
            &matching_logout,
        ),
        Err(SamlError::AssertionMatchesOutstandingLogout)
    ));
    assert!(matches!(
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            response_input(&base_response)?,
            post_validation(&mut replay_cache),
        ),
        Err(SamlError::ReplayDetected { .. })
    ));
    Ok(())
}

#[test]
fn exact_authn_context_opt_in_ignores_unselected_assertion_and_preserves_other_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .relay_state(RelayState::try_new("step-up")?)
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa.clone()),
        RespondSso::post().sign_response(),
    )?;
    let xml = String::from_utf8(
        STANDARD.decode(
            response
                .post_form()?
                .value("SAMLResponse")
                .ok_or("missing SAMLResponse")?,
        )?,
    )?;
    let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
    let selected = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == "Assertion")
        .ok_or("missing selected assertion")?;
    let selected_id = selected.attr("ID").ok_or("missing assertion ID")?;
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
        &xml[selected.start..confirmation.start],
        &xml[confirmation.end..selected.end],
    )
    .replacen(
        &format!("ID=\"{selected_id}\""),
        "ID=\"_unselected_mfa\"",
        1,
    );
    let weaker_selected =
        xml[selected.start..selected.end].replace(MFA, PASSWORD_PROTECTED_TRANSPORT);
    let edited = format!(
        "{}{unselected}{weaker_selected}{}",
        &xml[..selected.start],
        &xml[selected.end..]
    );
    let signed = resign_response_xml(&edited)?;

    assert!(matches!(
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::post(vec![
                FormField::new("SAMLResponse", STANDARD.encode(signed.as_bytes())),
                FormField::new("RelayState", "wrong-state"),
            ]),
            post_validation(&mut Default::default()),
        ),
        Err(SamlError::RelayStateMismatch { .. })
    ));

    let tampered = signed.replace("alice", "mallory");
    assert!(matches!(
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::post(vec![
                FormField::new("SAMLResponse", STANDARD.encode(tampered.as_bytes())),
                FormField::new("RelayState", "step-up"),
            ]),
            post_validation(&mut Default::default()),
        ),
        Err(SamlError::SignatureVerification { .. })
    ));

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(vec![
            FormField::new("SAMLResponse", STANDARD.encode(signed.as_bytes())),
            FormField::new("RelayState", "step-up"),
        ]),
        post_validation(&mut Default::default()),
    ) {
        Err(SamlError::AuthnContextMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, vec![mfa]);
            assert_eq!(
                actual,
                vec![AuthnContextReference::class(PASSWORD_PROTECTED_TRANSPORT)?]
            );
        }
        other => return Err(format!("expected AuthnContextMismatch, got {other:?}").into()),
    }

    let error_response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(
            Status::responder().with_subordinate(SubordinateStatusCode::no_authn_context()),
        ),
        RespondSso::post(),
    )?;
    assert!(matches!(
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            response_input(&error_response)?,
            post_validation(&mut Default::default()),
        ),
        Err(SamlError::StatusNotSuccess { .. })
    ));
    Ok(())
}

#[test]
fn non_opted_in_requests_and_old_snapshots_keep_existing_behavior(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().requested_authn_context(RequestedAuthnContext::try_new(
            AuthnContextComparison::Exact,
            [mfa.clone()],
        )?),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let base_response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa),
        RespondSso::post().sign_response(),
    )?;
    let different = resign_response_with_statements(
        &base_response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        different.clone(),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(
        session.authn_statements()[0]
            .authn_context()
            .class_reference()
            .map(AuthnContextReference::uri),
        Some(PASSWORD_PROTECTED_TRANSPORT)
    );

    let old_snapshot =
        PendingAuthnRequestSnapshot::new(started.pending.request_id().as_str(), IDP, "post", ACS);
    let old_pending = PendingAuthnRequest::from_snapshot(old_snapshot)?;
    assert_eq!(old_pending.required_authn_context(), None);
    sp.finish_sso(
        &idp_descriptor,
        &old_pending,
        different,
        post_validation(&mut Default::default()),
    )?;
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn old_json_snapshot_finishes_sso_without_authn_context_opt_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let base_response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa),
        RespondSso::post().sign_response(),
    )?;
    let different = resign_response_with_statements(
        &base_response,
        &format!(
            r#"<saml:AuthnStatement AuthnInstant="{{instant}}"><saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#
        ),
    )?;

    let old_json = format!(
        r#"{{"request_id":"{}","relay_state":null,"idp_entity_id":"{IDP}","acs_binding":"post","acs_url":"{ACS}","acs_index":null,"acs_is_default":true}}"#,
        started.pending.request_id().as_str()
    );
    let old_pending = PendingAuthnRequest::from_snapshot(serde_json::from_str(&old_json)?)?;
    assert_eq!(old_pending.required_authn_context(), None);
    sp.finish_sso(
        &idp_descriptor,
        &old_pending,
        different.clone(),
        post_validation(&mut Default::default()),
    )?;

    let new_json = serde_json::to_string(&started.pending.snapshot())?;
    let new_pending = PendingAuthnRequest::from_snapshot(serde_json::from_str(&new_json)?)?;
    assert!(matches!(
        sp.finish_sso(
            &idp_descriptor,
            &new_pending,
            different,
            post_validation(&mut Default::default()),
        ),
        Err(SamlError::AuthnContextMismatch { .. })
    ));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn exact_authn_context_opt_in_works_with_encrypted_assertions(
) -> Result<(), Box<dyn std::error::Error>> {
    use super::{parties_with, CERT, KEY};
    use crate::tests::common::signing_credentials;

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
    let mfa = AuthnContextReference::class(MFA)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .requested_authn_context(RequestedAuthnContext::try_new(
                AuthnContextComparison::Exact,
                [mfa.clone()],
            )?)
            .require_exact_authn_context(),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        request_input(&started.outbound)?,
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()).authn_context(mfa),
        RespondSso::post(),
    )?;
    sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        response_input(&response)?,
        post_validation(&mut Default::default()),
    )?;
    Ok(())
}
