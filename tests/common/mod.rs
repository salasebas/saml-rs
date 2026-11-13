use saml_rs::{CertificatePem, Credentials, PrivateKeyPem};

pub fn signing_credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(include_str!(
            "../fixtures/key/sp/privkey.unencrypted.pkcs8.pem"
        ))),
        signing_certificate: Some(CertificatePem::new(include_str!(
            "../fixtures/key/sp/cert.unencrypted.pkcs8.cer"
        ))),
        ..Credentials::default()
    }
}
