use base64::{engine::general_purpose::STANDARD, Engine};
use saml_rs::{
    AlgorithmPolicy, CertificatePem, Credentials, Outbound, OutboundDelivery, PrivateKeyPem,
    SignatureAlgorithm, X509Credential,
};
use url::Url;

pub(super) struct SigningFixture {
    pub(super) algorithm: SignatureAlgorithm,
    pub(super) uri: &'static str,
    signature_bytes: usize,
    key: &'static str,
    certificate: &'static str,
}

pub(super) const SIGNING_FIXTURES: &[SigningFixture] = &[
    SigningFixture {
        algorithm: SignatureAlgorithm::EcdsaSha256,
        uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        signature_bytes: 64,
        key: include_str!("../../tests/fixtures/key/prime256v1/privkey.pkcs8.pem"),
        certificate: include_str!("../../tests/fixtures/key/prime256v1/cert.pem"),
    },
    SigningFixture {
        algorithm: SignatureAlgorithm::EcdsaSha384,
        uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        signature_bytes: 96,
        key: include_str!("../../tests/fixtures/key/secp384r1/privkey.pkcs8.pem"),
        certificate: include_str!("../../tests/fixtures/key/secp384r1/cert.pem"),
    },
    SigningFixture {
        algorithm: SignatureAlgorithm::EcdsaSha512,
        uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        signature_bytes: 132,
        key: include_str!("../../tests/fixtures/key/secp521r1/privkey.pkcs8.pem"),
        certificate: include_str!("../../tests/fixtures/key/secp521r1/cert.pem"),
    },
    #[cfg(not(feature = "crypto-fips"))]
    SigningFixture {
        algorithm: SignatureAlgorithm::Ed25519,
        uri: "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
        signature_bytes: 64,
        key: include_str!("../../tests/fixtures/key/ed25519/privkey.pkcs8.pem"),
        certificate: include_str!("../../tests/fixtures/key/ed25519/cert.pem"),
    },
];

impl SigningFixture {
    pub(super) fn credentials(&self) -> Credentials {
        Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new(self.certificate),
            PrivateKeyPem::new(self.key),
        ))
    }

    pub(super) fn algorithms(&self) -> AlgorithmPolicy {
        AlgorithmPolicy {
            signature: self.algorithm.clone(),
            ..AlgorithmPolicy::default()
        }
    }

    pub(super) fn assert_signature<M>(
        &self,
        outbound: &Outbound<M>,
        message_field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match outbound.delivery() {
            OutboundDelivery::Redirect(url) => {
                let url = Url::parse(url)?;
                let fields: Vec<_> = url.query_pairs().collect();
                let value = |name| {
                    fields
                        .iter()
                        .find_map(|(field, value)| (field == name).then_some(value.as_ref()))
                };
                self.assert_detached_signature(value("SigAlg"), value("Signature"))?;
            }
            OutboundDelivery::PostForm(form) => {
                if let Some(algorithm) = form.value("SigAlg") {
                    self.assert_detached_signature(Some(algorithm), form.value("Signature"))?;
                } else {
                    let encoded = form.value(message_field).ok_or("missing SAML message")?;
                    self.assert_xml_signature(std::str::from_utf8(&STANDARD.decode(encoded)?)?)?;
                }
            }
            OutboundDelivery::SoapRequest(request) => {
                self.assert_xml_signature(request.envelope())?;
            }
            OutboundDelivery::SoapResponse(response) => {
                self.assert_xml_signature(response.envelope())?;
            }
        }
        Ok(())
    }

    fn assert_detached_signature(
        &self,
        algorithm: Option<&str>,
        signature: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(algorithm, Some(self.uri));
        let signature = STANDARD.decode(signature.ok_or("missing detached Signature")?)?;
        assert_eq!(signature.len(), self.signature_bytes, "{}", self.uri);
        Ok(())
    }

    fn assert_xml_signature(&self, xml: &str) -> Result<(), Box<dyn std::error::Error>> {
        let document = roxmltree::Document::parse(xml)?;
        let algorithm = document
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod"))
            })
            .ok_or("missing SignatureMethod")?;
        assert_eq!(algorithm.attribute("Algorithm"), Some(self.uri));
        Ok(())
    }
}

#[cfg(feature = "crypto-fips")]
#[test]
fn fips_rejects_ed25519_signing_in_both_builders() -> Result<(), saml_rs::SamlError> {
    use saml_rs::{AcsEndpoint, EntityId, IdpConfig, SamlError, SpConfig, SsoEndpoint};

    let credentials = Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(include_str!("../../tests/fixtures/key/ed25519/cert.pem")),
        PrivateKeyPem::new(include_str!(
            "../../tests/fixtures/key/ed25519/privkey.pkcs8.pem"
        )),
    ));
    for signature in [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Custom("http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519".into()),
    ] {
        let algorithms = AlgorithmPolicy {
            signature,
            ..AlgorithmPolicy::default()
        };
        let sp = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(credentials.clone())
        .algorithms(algorithms.clone())
        .build();
        let idp = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(credentials.clone())
        .algorithms(algorithms)
        .build();
        assert!(matches!(sp, Err(SamlError::Unsupported(_))));
        assert!(matches!(idp, Err(SamlError::Unsupported(_))));
    }
    Ok(())
}
