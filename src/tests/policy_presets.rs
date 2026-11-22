use saml_rs::{
    AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, IdpValidationPolicy, NameIdCreationPolicy,
    ResponseSignaturePolicy, SpValidationPolicy, XmlSignatureProfile,
};

#[test]
fn recommended_presets_select_the_classified_validation() {
    assert_eq!(
        SpValidationPolicy::default(),
        SpValidationPolicy {
            assertions: AssertionSignaturePolicy::AllowUnsigned,
            responses: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
            authn_requests: AuthnRequestSigningPolicy::DoNotSign,
            audience: AudienceValidationPolicy::EvaluatePresentRestrictions,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
        }
    );
    assert_eq!(
        IdpValidationPolicy::default(),
        IdpValidationPolicy {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsigned,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
        }
    );
}
