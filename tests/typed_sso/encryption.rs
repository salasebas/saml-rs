use super::*;
use saml_rs::{AlgorithmPolicy, DataEncryptionAlgorithm, DecryptionCredential};

fn encrypted_exchange(
    algorithm: DataEncryptionAlgorithm,
) -> Result<SsoExchange, Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_with_validation_and_xml(SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        ..recommended_sso_accept_validation()
    })?)?;
    let mut idp_config = idp_with_validation_and_xml(recommended_sso_accept_idp_validation())?;
    idp_config.algorithms = AlgorithmPolicy {
        data_encryption: algorithm,
        ..AlgorithmPolicy::default()
    };
    let idp = Saml::idp(idp_config)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post().allow_unsigned_encrypted_cbc(),
    )?;
    Ok(SsoExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields: post_fields(&response)?,
    })
}

#[test]
fn typed_encrypted_cbc_response_is_signed_by_default() -> Result<(), Box<dyn std::error::Error>> {
    for algorithm in [
        DataEncryptionAlgorithm::Aes256,
        DataEncryptionAlgorithm::Custom("http://www.w3.org/2001/04/xmlenc#aes192-cbc".into()),
    ] {
        let exchange = encrypted_exchange(algorithm)?;
        let response = exchange.idp.respond_sso(
            &exchange.sp_descriptor,
            &exchange.received,
            subject(),
            RespondSso::post(),
        )?;
        let fields = post_fields(&response)?;
        let xml = response_xml_from_fields(&fields)?;
        assert!(parse(&xml)?
            .root
            .children
            .iter()
            .any(|child| child.local_name == "Signature"));
        let session = exchange.sp.finish_sso(
            &exchange.idp_descriptor,
            &exchange.pending,
            BrowserInput::<SsoResponse>::post(fields),
            validation(),
        )?;
        assert_eq!(session.name_id().value(), "alice@example.com");
    }
    Ok(())
}

#[test]
fn recommended_sso_accept_rejects_unsigned_cbc_response_unless_relaxed(
) -> Result<(), Box<dyn std::error::Error>> {
    let accepting = Saml::sp(sp_with_validation_and_xml(
        recommended_sso_accept_validation(),
    )?)?;
    let relaxed = Saml::sp(sp_with_validation_and_xml(SpValidationPolicy {
        responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
        ..recommended_sso_accept_validation()
    })?)?;
    for algorithm in [
        DataEncryptionAlgorithm::Aes128,
        DataEncryptionAlgorithm::Custom("http://www.w3.org/2001/04/xmlenc#aes192-cbc".into()),
        DataEncryptionAlgorithm::Aes256,
    ] {
        let exchange = encrypted_exchange(algorithm)?;
        let fields = exchange.response_fields;
        let xml = response_xml_from_fields(&fields)?;
        for variant in [
            xml.clone(),
            xml.replacen("<xenc:EncryptionMethod ", "<xenc:EncryptionMethod xmlns:Algorithm=\"urn:shadow\" ", 1),
            xml.replacen("<xenc:EncryptionMethod ", "<xenc:EncryptionMethod xmlns:other=\"urn:attributes\" other:Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\" ", 1),
            xml.replacen("<xenc:EncryptionMethod ", "<foreign:EncryptionMethod xmlns:foreign=\"urn:foreign\" Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/><xenc:EncryptionMethod ", 1),
        ] {
            let result = accepting.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                BrowserInput::<SsoResponse>::post(response_fields_with_xml(fields.clone(), &variant)?),
                validation(),
            );
            assert!(matches!(result, Err(SamlError::SignatureMissing)), "unsigned CBC accepted or wrong error");
            let session = relaxed.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                BrowserInput::<SsoResponse>::post(response_fields_with_xml(fields.clone(), &variant)?),
                validation(),
            )?;
            assert_eq!(session.name_id().value(), "alice@example.com");
        }
    }
    Ok(())
}

#[test]
fn recommended_sso_accept_rejects_missing_and_unknown_data_methods(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = encrypted_exchange(DataEncryptionAlgorithm::Aes256Gcm)?;
    let xml = response_xml_from_fields(&exchange.response_fields)?;
    let algorithm = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    for (variant, expected) in [
        (
            xml.replacen(algorithm, "urn:unknown", 1),
            SamlError::Unsupported(
                "unsupported encrypted assertion data algorithm: urn:unknown".into(),
            ),
        ),
        (
            xml.replacen(&format!("Algorithm=\"{algorithm}\""), "", 1),
            SamlError::Crypto("missing EncryptionMethod Algorithm".into()),
        ),
        (
            xml.replacen(
                &format!("<xenc:EncryptionMethod Algorithm=\"{algorithm}\"/>"),
                "",
                1,
            ),
            SamlError::Crypto("missing EncryptionMethod Algorithm".into()),
        ),
    ] {
        let result = exchange.sp.finish_sso(
            &exchange.idp_descriptor,
            &exchange.pending,
            BrowserInput::<SsoResponse>::post(response_fields_with_xml(
                exchange.response_fields.clone(),
                &variant,
            )?),
            validation(),
        );
        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some(expected.to_string())
        );
    }
    Ok(())
}

#[test]
fn unsigned_gcm_acceptance_bounds_key_work_including_rollover(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = encrypted_exchange(DataEncryptionAlgorithm::Aes256Gcm)?;
    let xml = response_xml_from_fields(&exchange.response_fields)?;
    let document = bergshamra::xml::uppsala::parse(&xml)?;
    let key = document
        .descendants(document.root())
        .into_iter()
        .find(|node| {
            document.element(*node).is_some_and(|element| {
                element.matches_name_ns("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")
            })
        })
        .ok_or("missing key")?;
    let range = document.node_range(key).ok_or("missing key range")?;
    let candidate = &xml[range];
    let mut config = sp_with_validation_and_xml(recommended_sso_accept_validation())?;
    config.credentials.decryption_key = Some(PrivateKeyPem::new(include_str!(
        "../fixtures/key/idp/provider_matrix_privkey.pkcs8.pem"
    )));
    config.credentials.encryption_certificate = Some(CertificatePem::new(include_str!(
        "../fixtures/key/idp/cert.cer"
    )));
    config.credentials.additional_decryption_keys = vec![DecryptionCredential {
        certificate: CertificatePem::new(CERT),
        key: PrivateKeyPem::new(PRIVKEY),
        passphrase: None,
    }];
    let rollover = Saml::sp(config)?;
    for count in [1, 15, 16] {
        let crowded = xml.replacen(candidate, &candidate.repeat(count), 1);
        for variant in [crowded.clone(), resign_response(&crowded)?] {
            let result = rollover.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                BrowserInput::<SsoResponse>::post(response_fields_with_xml(
                    exchange.response_fields.clone(),
                    &variant,
                )?),
                validation(),
            );
            if count <= 15 {
                assert_eq!(result?.name_id().value(), "alice@example.com");
            } else {
                assert!(
                    matches!(result, Err(SamlError::Invalid(message)) if message.contains("ERR_DECRYPTION_LIMIT_EXCEEDED")),
                    "excess rollover work was not refused"
                );
            }
        }
    }
    Ok(())
}
