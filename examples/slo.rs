//! End-to-end typed Single Logout after a typed SSO session.
//!
//! Run with: `cargo run -p saml-rs --example slo`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
        IdpDescriptor, IdpValidationPolicy, LogoutRequest, LogoutResponse, MetadataTrustPolicy,
        NameId, PrivateKeyPem, ReplayPolicy, RespondSlo, RespondSso, Saml, SamlValidationContext,
        SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse,
        StartSlo, StartSso, Subject,
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
            .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo")?)
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
            .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo")?)
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

    let sso = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(sso.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::post(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &sso.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let subject = session
        .logout_subject()
        .ok_or("session has no logout subject")?;
    let logout = sp.start_slo(&idp_descriptor, subject, StartSlo::post())?;
    println!("SP  -> LogoutRequest id = {}", logout.pending.id().as_str());

    let logout_request = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(logout.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let logout_response = idp.respond_slo(&sp_descriptor, &logout_request, RespondSlo::post())?;
    let completed = sp.finish_slo(
        &idp_descriptor,
        &logout.pending,
        BrowserInput::<LogoutResponse>::post(logout_response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    println!(
        "SP  <- LogoutResponse status = {}",
        completed.status().unwrap_or("missing")
    );
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
