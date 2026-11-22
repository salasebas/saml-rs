//! End-to-end typed Single Logout after a typed SSO session.
//!
//! Run with: `cargo run -p saml-rs --example slo`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AcsEndpoint, CertificatePem, Credentials, EntityId, IdentityProvider, IdpConfig,
        IdpDescriptor, Inbound, MetadataTrustPolicy, NameId, NameIdFormat, PrivateKeyPem,
        ReplayPolicy, RespondSlo, RespondSso, SamlValidationContext, ServiceProvider, SloEndpoint,
        SpConfig, SpDescriptor, SsoAssertion, SsoEndpoint, StartSlo, StartSso, Status,
        X509Credential,
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
    // A deployment passes a shared replay cache with ReplayPolicy::RequireCache.
    let validation = || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled);

    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo")?)
        .credentials(credentials())
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo")?)
        .credentials(credentials())
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

    let sso = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(sso.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        SsoAssertion::new(NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)),
        RespondSso::post(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &sso.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let subject = session
        .logout_subject()
        .ok_or("session has no logout subject")?;
    let logout = sp.start_slo(&idp_descriptor, subject, StartSlo::post())?;
    println!(
        "SP  -> LogoutRequest id = {}",
        logout.pending.request_id().as_str()
    );

    let logout_request = idp.receive_slo(
        &sp_descriptor,
        Inbound::post(logout.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let logout_response = idp.respond_slo(
        &sp_descriptor,
        &logout_request,
        &Status::success(),
        RespondSlo::post(),
    )?;
    let completed = sp.finish_slo(
        &idp_descriptor,
        &logout.pending,
        Inbound::post(logout_response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    println!(
        "SP  <- LogoutResponse status = {}",
        completed.response().status().top_level().as_uri()
    );
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
