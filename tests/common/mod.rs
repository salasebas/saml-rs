use saml_rs::{CertificatePem, Credentials, PrivateKeyPem, X509Credential};

pub fn signing_credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(include_str!(
            "../fixtures/key/sp/cert.unencrypted.pkcs8.cer"
        )),
        PrivateKeyPem::new(include_str!(
            "../fixtures/key/sp/privkey.unencrypted.pkcs8.pem"
        )),
    ))
}
