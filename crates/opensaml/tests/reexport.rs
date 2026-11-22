use std::any::TypeId;

#[test]
fn opensaml_reexports_canonical_error_type() {
    assert_eq!(
        TypeId::of::<opensaml::SamlError>(),
        TypeId::of::<saml_rs::SamlError>(),
    );

    let _: Option<opensaml::ServiceProvider> = None;
}

#[test]
#[expect(deprecated, reason = "this test verifies the supported legacy alias")]
fn opensaml_reexports_deprecated_legacy_error_alias() {
    assert_eq!(
        TypeId::of::<opensaml::OpenSamlError>(),
        TypeId::of::<saml_rs::SamlError>(),
    );
}
