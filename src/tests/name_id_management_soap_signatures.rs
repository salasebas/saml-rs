use std::time::{Duration, SystemTime};

use bergshamra::{DsigContext, KeysManager};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::transform_algorithm::{C14N, ENVELOPED_SIGNATURE};
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::{
    AcsEndpoint, CertificatePem, Credentials, EndpointUrl, EntityId, IdentityProvider, IdpConfig,
    InMemoryReplayCache, ManageNameIdService, MetadataTrustPolicy, NameId, NameIdChange,
    NameIdManagementReceipt, PrivateKeyPem, ReplayPolicy, SamlError, SamlValidationContext,
    ServiceProvider, SignatureConfig, SoapBodyElement, SoapChannel, SoapResponse, SpConfig,
    SpDescriptor, SsoEndpoint, StartNameIdManagement, X509Credential,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const IDP: &str = "https://idp.example.com/metadata";
const SP: &str = "https://sp.example.com/metadata";
const IDP_MANAGE: &str = "https://idp.example.com/manage";
const SP_MANAGE: &str = "https://sp.example.com/manage";
const SP_KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const PRIOR_KEY: &str =
    include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const PRIOR_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");

fn providers() -> Result<(IdentityProvider, SpDescriptor, SpDescriptor), Box<dyn std::error::Error>>
{
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(IDP_MANAGE)?))
        .build()?,
    );
    let sp = SpConfig::builder(
        EntityId::try_new(SP)?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    );
    let descriptor = |key, cert| -> Result<SpDescriptor, SamlError> {
        let credentials = Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new(cert),
            PrivateKeyPem::new(key),
        ));
        let metadata = ServiceProvider::new(sp.clone().credentials(credentials).build()?)
            .metadata_xml()
            .replacen("<AssertionConsumerService", &format!(r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="{SP_MANAGE}"/><AssertionConsumerService"#), 1);
        SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP)?,
            &metadata,
            MetadataTrustPolicy::AllowUnsigned,
        )
    };
    Ok((
        idp,
        descriptor(SP_KEY, SP_CERT)?,
        descriptor(PRIOR_KEY, PRIOR_CERT)?,
    ))
}

fn sign(xml: &str, config: Option<&SignatureConfig>) -> Result<String, SamlError> {
    let key = read_private_key(SP_KEY, None)?;
    sign_saml_xml(xml, true, &key, SP_CERT, RSA_SHA256, &[], config)
}

fn sign_in_soap_body(
    message: &str,
    reference_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{C14N}"/>
            <ds:SignatureMethod Algorithm="{RSA_SHA256}"/>
            <ds:Reference URI="#{reference_id}">
              <ds:Transforms>
                <ds:Transform Algorithm="{ENVELOPED_SIGNATURE}"/>
                <ds:Transform Algorithm="{C14N}"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue/>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue/>
        </ds:Signature>"##
    );
    let message = message.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
    let envelope = format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body xml:lang="en">{message}</soap:Body></soap:Envelope>"#
    );
    let mut keys = KeysManager::new();
    keys.add_key(read_private_key(SP_KEY, None)?);
    Ok(bergshamra::sign(&DsigContext::new(keys), &envelope)?)
}

#[test]
fn soap_manage_name_id_request_checks_the_unqualified_id() -> TestResult {
    let (idp, sp, _) = providers()?;
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
              <saml:Issuer>{SP}</saml:Issuer>
              <saml:NameID>current-value</saml:NameID>
              <samlp:Terminate/>
            </samlp:ManageNameIDRequest>"#
    );
    let xml = sign(&xml, None)?.replacen(" ID=", r#" xmlns:ID="urn:test" ID="#, 1);
    let envelope = saml_rs::SoapRequest::try_new(EndpointUrl::try_new(IDP_MANAGE)?, &xml)?;
    let receipt = idp.receive_name_id_management(
        &sp,
        envelope.envelope(),
        SoapChannel::mutually_authenticated_confidential(),
        SamlValidationContext::new(SystemTime::UNIX_EPOCH, ReplayPolicy::NoCache),
    )?;
    assert!(matches!(receipt, NameIdManagementReceipt::Request(_)));
    Ok(())
}

#[test]
fn soap_manage_name_id_response_verifies_in_the_original_envelope() -> TestResult {
    let (idp, sp, _) = providers()?;
    let started = idp.start_name_id_management(
        &sp,
        &NameId::persistent("current-value")?,
        &NameIdChange::Terminate,
        StartNameIdManagement::new(),
        SoapChannel::mutually_authenticated_confidential(),
    )?;
    let request = SoapBodyElement::from_envelope(started.request().envelope())?;
    let request_id =
        crate::xml::protocol_element::parse_saml(request.xml())?.required_attr("ID")?;
    let message = format!(
        r#"<samlp:ManageNameIDResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}">
              <saml:Issuer>{SP}</saml:Issuer>
              <samlp:Extensions ID="_extra"><ext:Data xmlns:ext="urn:test"/></samlp:Extensions>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            </samlp:ManageNameIDResponse>"#
    );
    let signed = sign_in_soap_body(&message, "_response")?;
    started.finish(&signed)?;
    let header = r#"<soap:Header><ext:AttachmentSignature xmlns:ext="urn:test:attachment" soap:actor="https://archive.example.com/soap" soap:mustUnderstand="1">
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>
            <ds:Reference URI="cid:document@example.com"/>
        </ds:SignedInfo></ds:Signature>
    </ext:AttachmentSignature></soap:Header>"#;
    let with_header = signed.replacen("<soap:Body", &format!("{header}<soap:Body"), 1);
    started.finish(&with_header)?;
    let result = started.finish(&sign_in_soap_body(&message, "_extra")?);
    assert!(
        matches!(result, Err(SamlError::SignedReferenceMismatch)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn soap_manage_name_id_request_verifies_the_sp_signature() -> TestResult {
    let (idp, sp, stale_sp) = providers()?;
    let channel = SoapChannel::mutually_authenticated_confidential();
    let xml = format!(
        r#"<samlp:ManageNameIDRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{IDP_MANAGE}">
            <saml:Issuer>{SP}</saml:Issuer>
            <samlp:Extensions><ext:Data xmlns:ext="urn:test"/></samlp:Extensions>
            <saml:NameID>current-value</saml:NameID>
            <samlp:Terminate/>
        </samlp:ManageNameIDRequest>"#
    );
    let misplaced = SignatureConfig {
        reference: Some(
            "/*[local-name(.)='ManageNameIDRequest']/*[local-name(.)='Extensions']".into(),
        ),
        ..SignatureConfig::default()
    };
    let destination = EndpointUrl::try_new(IDP_MANAGE)?;
    let misplaced =
        saml_rs::SoapRequest::try_new(destination.clone(), &sign(&xml, Some(&misplaced))?)?;
    let result = idp.receive_name_id_management(
        &sp,
        misplaced.envelope(),
        channel,
        SamlValidationContext::new(SystemTime::UNIX_EPOCH, ReplayPolicy::NoCache),
    );
    assert!(
        matches!(result, Err(SamlError::ProtocolProfile(_))),
        "{result:?}"
    );
    let request = saml_rs::SoapRequest::try_new(destination, &sign(&xml, None)?)?;
    let mut cache = InMemoryReplayCache::with_clock(|| SystemTime::UNIX_EPOCH);
    fn validation(cache: &mut InMemoryReplayCache) -> SamlValidationContext<'_> {
        SamlValidationContext::new(SystemTime::UNIX_EPOCH, ReplayPolicy::RequireCache(cache))
            .with_replay_retention(Duration::from_secs(300))
    }
    let result = idp.receive_name_id_management(
        &stale_sp,
        request.envelope(),
        channel,
        validation(&mut cache),
    );
    assert!(
        matches!(result, Err(SamlError::SignatureVerification { .. })),
        "{result:?}"
    );
    let receipt =
        idp.receive_name_id_management(&sp, request.envelope(), channel, validation(&mut cache))?;
    let NameIdManagementReceipt::Request(request) = receipt else {
        return Err("signed request was refused".into());
    };
    assert_eq!(request.message().change(), &NameIdChange::Terminate);
    Ok(())
}

#[test]
fn soap_manage_name_id_response_verifies_the_sp_signature() -> TestResult {
    let (idp, sp, stale_sp) = providers()?;
    for (peer, trusted) in [(&stale_sp, false), (&sp, true)] {
        let started = idp.start_name_id_management(
            peer,
            &NameId::persistent("current-value")?,
            &NameIdChange::Terminate,
            StartNameIdManagement::new(),
            SoapChannel::mutually_authenticated_confidential(),
        )?;
        let request = SoapBodyElement::from_envelope(started.request().envelope())?;
        let request = crate::xml::protocol_element::parse_saml(request.xml())?;
        let request_id = request.required_attr("ID")?;
        let xml = sign(
            &format!(
                r#"<samlp:ManageNameIDResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}">
                <saml:Issuer>{SP}</saml:Issuer>
                <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            </samlp:ManageNameIDResponse>"#
            ),
            None,
        )?;
        let response = SoapResponse::try_new(&xml)?;
        let result = started.finish(response.envelope());
        if trusted {
            result?;
        } else {
            assert!(
                matches!(result, Err(SamlError::SignatureVerification { .. })),
                "{result:?}"
            );
        }
    }
    Ok(())
}
