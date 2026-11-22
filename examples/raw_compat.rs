//! Low-level samlify-port SSO example on the raw API.
//!
//! `SpValidationPolicy::compatibility` is the typed name for keeping this
//! behavior on the builders. New browser integrations should start with
//! `examples/sso.rs`. This example is for callers that need direct access to
//! raw `ServiceProvider`, `IdentityProvider`, `HttpRequest`, or `FlowResult`
//! values.

#[cfg(crypto)]
#[allow(deprecated)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::constants::signature_algorithm::RSA_SHA256;
    use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
    use saml_rs::raw::{
        Binding, EntitySetting, HttpRequest, IdentityProvider, LoginRequestOptions,
        LoginResponseOptions, ServiceProvider, User,
    };

    let privkey = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    let cert = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    let signing = || {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(privkey.into());
        setting.signing_cert = Some(cert.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    };

    let mut idp_metadata = IdpMetadataInput::default();
    idp_metadata.entity_id = "https://idp.example.com/metadata".into();
    idp_metadata.signing_certs = vec![cert.into()];
    idp_metadata.want_authn_requests_signed = true;
    idp_metadata.single_sign_on_service =
        vec![Endpoint::new(Binding::Post, "https://idp.example.com/sso")];
    let idp = IdentityProvider::from_config(&idp_metadata, signing())?;
    let mut sp_metadata = SpMetadataInput::default();
    sp_metadata.entity_id = "https://sp.example.com/metadata".into();
    sp_metadata.authn_requests_signed = true;
    sp_metadata.want_assertions_signed = true;
    sp_metadata.signing_certs = vec![cert.into()];
    sp_metadata.assertion_consumer_service =
        vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
    let sp = ServiceProvider::from_config(&sp_metadata, signing())?;

    let request = sp.create_login_request(&idp, Binding::Post, &LoginRequestOptions::default())?;
    let parsed = idp.parse_login_request(
        &sp,
        Binding::Post,
        &HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]),
    )?;
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: parsed.extract.get_str("request.id"),
            ..Default::default()
        },
    )?;
    let result = sp.parse_login_response_with_request_id(
        &idp,
        Binding::Post,
        &HttpRequest::post(vec![("SAMLResponse".into(), response.context)]),
        &request.id,
    )?;
    println!(
        "samlify-port raw authenticated = {:?}",
        result.extract.get_str("nameID")
    );
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
