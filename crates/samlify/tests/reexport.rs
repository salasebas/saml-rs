use std::any::TypeId;

#[test]
fn samlify_reexports_canonical_saml_error_type() {
    assert_eq!(
        TypeId::of::<samlify::SamlError>(),
        TypeId::of::<saml_rs::SamlError>()
    );

    let _: Option<samlify::ServiceProvider> = None;
}
