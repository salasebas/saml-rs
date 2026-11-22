use std::any::TypeId;

#[test]
fn samlet_reexports_canonical_saml_error_type() {
    assert_eq!(
        TypeId::of::<samlet::SamlError>(),
        TypeId::of::<saml_rs::SamlError>()
    );

    let _: Option<samlet::ServiceProvider> = None;
}
