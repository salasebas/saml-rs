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
            assertion_signatures: AssertionSignaturePolicy::AllowUnsigned,
            response_signatures: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
            authn_request_signing: AuthnRequestSigningPolicy::DoNotSign,
            audience: AudienceValidationPolicy::EvaluatePresentRestrictions,
            name_id_creation: NameIdCreationPolicy::AllowCreate,
        }
    );
    assert_eq!(
        IdpValidationPolicy::default(),
        IdpValidationPolicy {
            authn_request_signatures: AuthnRequestValidationPolicy::AllowUnsigned,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
        }
    );
}
