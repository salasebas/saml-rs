use saml_rs::{CertificatePem, Credentials, PrivateKeyPem};

pub fn signing_credentials() -> Credentials {
    Credentials::default()
        .with_signing_key(PrivateKeyPem::new(include_str!(
            "../fixtures/key/sp/privkey.unencrypted.pkcs8.pem"
        )))
        .with_signing_certificate(CertificatePem::new(include_str!(
            "../fixtures/key/sp/cert.unencrypted.pkcs8.cer"
        )))
}
