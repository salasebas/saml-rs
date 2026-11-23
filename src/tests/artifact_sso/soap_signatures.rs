use bergshamra::core::algorithm::HMAC_SHA256;
use bergshamra::{DsigContext, Key, KeysManager};
use saml_rs::crypto::keys::load_hmac_secret;
use saml_rs::{
    CertificatePem, Credentials, HmacSecret, IdpValidationPolicy, PrivateKeyPem,
    SoapProtocolMessage, SoapResponse, SpValidationPolicy, X509Credential, XmlSignatureProfile,
};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const IDP_KEY: &str =
    include_str!("../../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_CERT: &str = include_str!("../../../tests/fixtures/key/idp/cert.cer");

fn signature_parties(
    artifact: AcsEndpoint,
    xml_signatures: XmlSignatureProfile,
) -> Result<Parties, SamlError> {
    let (idp, sp) = artifact_config_builders(AcsEndpoint::post(SP_ACS_POST)?, artifact)?;
    let idp_credential =
        X509Credential::new(CertificatePem::new(IDP_CERT), PrivateKeyPem::new(IDP_KEY));
    build_parties(
        idp.credentials(Credentials::default().with_signing_credential(idp_credential))
            .validation(IdpValidationPolicy {
                xml_signatures,
                ..IdpValidationPolicy::default()
            }),
        sp.credentials(signing_credentials())
            .validation(SpValidationPolicy {
                xml_signatures,
                ..SpValidationPolicy::default()
            }),
    )
}

fn sign_rsa(envelope: &str, private_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    sign_in_envelope(
        envelope,
        read_private_key(private_key, None)?,
        RSA_SHA256,
        transform_algorithm::C14N,
    )
}

fn sign_in_envelope(
    envelope: &str,
    key: Key,
    signature_method: &str,
    c14n: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let message = SoapProtocolMessage::from_envelope(envelope)?;
    let id = crate::xml::protocol_element::parse_saml(message.xml())?.required_attr("ID")?;
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{c14n}"/>
            <ds:SignatureMethod Algorithm="{signature_method}"/>
            <ds:Reference URI="#{id}">
              <ds:Transforms>
                <ds:Transform Algorithm="{enveloped}"/>
                <ds:Transform Algorithm="{c14n}"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue/>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue/>
        </ds:Signature>"##,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
    );
    let envelope = envelope
        .replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1)
        .replacen("<soap:Body>", r#"<soap:Body xml:lang="en">"#, 1);
    let mut keys = KeysManager::new();
    keys.add_key(key);
    Ok(bergshamra::sign(&DsigContext::new(keys), &envelope)?)
}

#[test]
fn artifact_resolve_signature_failure_leaves_the_artifact_outstanding() -> TestResult {
    let parties = signature_parties(
        AcsEndpoint::artifact(SP_ACS_ARTIFACT)?.with_default(),
        XmlSignatureProfile::ExcludeWeakAlgorithms,
    )?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let outbound = parties.idp.initiate_sso_artifact(
        &parties.sp_metadata,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&outbound)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        delivered.artifact(),
        channel,
        validation(),
    )?;
    let request = resolution.request().envelope();
    let result = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &sign_rsa(request, IDP_KEY)?,
        &mut issued,
        channel,
    );
    assert!(
        matches!(result, Err(SamlError::SignatureVerification { .. })),
        "{result:?}"
    );

    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &sign_rsa(request, PRIVKEY)?,
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(&sign_rsa(answer.response().envelope(), IDP_KEY)?)?;
    let session = parties.sp.accept_unsolicited_sso(
        &parties.idp_metadata,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn artifact_response_signature_precedes_status_and_does_not_authenticate_inner_sso() -> TestResult {
    let parties = signature_parties(
        AcsEndpoint::artifact(SP_ACS_ARTIFACT)?,
        XmlSignatureProfile::ExcludeWeakAlgorithms,
    )?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let artifact = parties
        .idp
        .issue_artifact(&parties.sp_metadata, &xml, 0, &mut issued)?;
    let delivered = DeliveredArtifact::from_form(&[FormField::new("SAMLart", artifact.as_str())])?;
    let channel = confidential();
    let resolution =
        parties
            .sp
            .resolve_artifact(&parties.idp_metadata, &artifact, channel, validation())?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);

    let envelope = answer.response().envelope();
    let result = resolution.finish(&sign_rsa(envelope, PRIVKEY)?);
    assert!(
        matches!(result, Err(SamlError::SignatureVerification { .. })),
        "{result:?}"
    );

    let resolved = resolution.finish(&sign_rsa(envelope, IDP_KEY)?)?;
    let login = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    );
    assert!(
        matches!(login, Err(SamlError::SignatureMissing)),
        "{login:?}"
    );

    let message = SoapProtocolMessage::from_envelope(envelope)?;
    let failure = message
        .xml()
        .replacen("status:Success", "status:Responder", 1)
        .replace(&xml, "");
    let failure = SoapResponse::try_new(&failure)?;
    let result = resolution.finish(&sign_rsa(failure.envelope(), PRIVKEY)?);
    assert!(
        matches!(result, Err(SamlError::SignatureVerification { .. })),
        "{result:?}"
    );
    let result = resolution.finish(&sign_rsa(failure.envelope(), IDP_KEY)?);
    assert!(
        matches!(result, Err(SamlError::StatusNotSuccess { .. })),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn soap_artifact_hmac_signatures_use_the_receivers_profile() -> TestResult {
    let sp_secret = HmacSecret::try_new(b"artifact SP fixture signing secret".as_slice())?;
    let idp_secret = HmacSecret::try_new(b"artifact IdP fixture signing secret".as_slice())?;
    let sign = |envelope: &str, secret: &HmacSecret| {
        sign_in_envelope(
            envelope,
            load_hmac_secret(secret)?,
            HMAC_SHA256,
            transform_algorithm::EXC_C14N,
        )
    };
    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let parties = signature_parties(
            AcsEndpoint::artifact(SP_ACS_ARTIFACT)?.with_default(),
            profile,
        )?;
        let sp_descriptor = parties.sp_metadata.with_hmac_secret(sp_secret.clone());
        let idp_descriptor = parties.idp_metadata.with_hmac_secret(idp_secret.clone());
        let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
        let outbound = parties.idp.initiate_sso_artifact(
            &sp_descriptor,
            SsoAssertion::new(principal()),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            &mut issued,
        )?;
        let delivered = delivered_by(&outbound)?;
        let channel = confidential();
        let resolution = parties.sp.resolve_artifact(
            &idp_descriptor,
            delivered.artifact(),
            channel,
            validation(),
        )?;
        let request = resolution.request().envelope();
        let answer = parties.idp.answer_artifact_resolve(
            &sp_descriptor,
            &sign(request, &sp_secret)?,
            &mut issued,
            channel,
        );
        let answer = if profile == XmlSignatureProfile::StrictRsaSha2 {
            assert!(
                matches!(answer, Err(SamlError::AlgorithmUnsupported)),
                "{answer:?}"
            );
            parties
                .idp
                .answer_artifact_resolve(&sp_descriptor, request, &mut issued, channel)?
        } else {
            answer?
        };
        assert_eq!(answer.release(), ArtifactRelease::Returned);

        let response = sign(answer.response().envelope(), &idp_secret)?;
        let resolved = resolution.finish(&response);
        if profile == XmlSignatureProfile::StrictRsaSha2 {
            assert!(
                matches!(resolved, Err(SamlError::AlgorithmUnsupported)),
                "{resolved:?}"
            );
        } else {
            assert_eq!(resolved?.local_name(), "Response");
        }
    }
    Ok(())
}
