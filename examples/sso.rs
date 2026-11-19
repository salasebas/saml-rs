//! End-to-end typed SSO: SP starts an `AuthnRequest`, the IdP receives it and
//! issues a signed `Response`, and the SP finishes with a typed session.
//!
//! Run with: `cargo run -p saml-rs --example sso`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AcsEndpoint, CertificatePem, Credentials, EntityId, IdpConfig, IdpDescriptor,
        IdpValidationPolicy, Inbound, MetadataTrustPolicy, NameId, PrivateKeyPem, RelayState,
        ReplayPolicy, RespondSso, Saml, SamlValidationContext, SpConfig, SpDescriptor,
        SpValidationPolicy, SsoEndpoint, StartSso, X509Credential,
    };
    use std::time::SystemTime;

    let privkey = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    let cert = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    let credentials = || {
        Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new(cert),
            PrivateKeyPem::new(privkey),
        ))
    };
    // Disabled preserves the raw API, which has no replay cache.
    let validation = || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled);

    let sp = Saml::sp(
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(credentials())
        .validation(SpValidationPolicy::recommended())
        .build()?,
    );
    let idp = Saml::idp(
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(credentials())
        .validation(IdpValidationPolicy::recommended())
        .build()?,
    );

    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.com/metadata")?,
        sp.metadata_xml(),
        // AllowUnsigned preserves an unsigned samlify-port metadata import.
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        // AllowUnsigned preserves an unsigned samlify-port metadata import.
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    let relay_state = RelayState::try_new("demo-state")?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    println!(
        "SP  -> AuthnRequest id = {}",
        started.pending.request_id().as_str()
    );

    let request = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    println!(
        "IdP <- request issuer  = {}",
        request.message().issuer().as_str()
    );

    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        &NameId::new("alice@example.com"),
        RespondSso::post(),
    )?;

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        validation(),
    );
    let session = session?;
    println!("SP  <- authenticated   = {}", session.name_id().value());
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
