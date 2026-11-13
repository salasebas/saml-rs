//! End-to-end typed SSO: SP starts an `AuthnRequest`, the IdP receives it and
//! issues a signed `Response`, and the SP finishes with a typed session.
//!
//! Run with: `cargo run -p saml-rs --example sso`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
        IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem,
        RelayStateParam, ReplayPolicy, RespondSso, Saml, SamlValidationContext, SpConfig,
        SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, StartSso, Subject,
    };
    use std::time::SystemTime;

    let privkey = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    let cert = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    let credentials = || Credentials {
        signing_key: Some(PrivateKeyPem::new(privkey)),
        signing_certificate: Some(CertificatePem::new(cert)),
        ..Credentials::default()
    };
    // DisabledForCompatibility preserves the raw API, which has no replay cache.
    let validation =
        || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);

    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;

    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        sp.metadata_xml(),
        // UnsignedForCompatibility preserves an unsigned samlify-port metadata import.
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        // UnsignedForCompatibility preserves an unsigned samlify-port metadata import.
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let relay_state = RelayStateParam::try_from_option(Some("demo-state".to_string()))?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    println!(
        "SP  -> AuthnRequest id = {}",
        started.pending.request_id().as_str()
    );

    let request = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    println!(
        "IdP <- request issuer  = {}",
        request.message().issuer().as_str()
    );

    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::post(),
    )?;

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
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
