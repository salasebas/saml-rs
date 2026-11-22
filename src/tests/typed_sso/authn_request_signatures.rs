use super::*;

#[test]
fn simplesign_checks_the_xml_signing_key_during_rollover() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::simple_sign())?;
    let xml = authn_request_xml(&started.outbound)?;
    let current = read_private_key(PRIVKEY, None)?;
    let next = read_private_key(
        include_str!("../../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem"),
        None,
    )?;
    let next_cert = include_str!("../../../tests/fixtures/key/idp/cert.cer");
    let receive = |xml_key, cert| -> Result<_, SamlError> {
        let signed = sign_saml_xml(&xml, true, xml_key, cert, RSA_SHA256, &[], None)?;
        let octet =
            crate::binding::build_simplesign_octet("SAMLRequest", &signed, None, RSA_SHA256);
        let fields = vec![
            FormField::new("SAMLRequest", STANDARD.encode(&signed)),
            FormField::new("SigAlg", RSA_SHA256),
            FormField::new(
                "Signature",
                sign_octet_string(&octet, &current, RSA_SHA256)?,
            ),
        ];
        idp.receive_sso(&sp_descriptor, Inbound::simple_sign(fields), validation())
    };
    assert_eq!(
        receive(&current, CERT)?.message().id(),
        started.pending.request_id()
    );
    assert!(matches!(
        receive(&next, next_cert),
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature
        })
    ));
    Ok(())
}
