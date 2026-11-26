use super::*;
use saml_rs::metadata::IdpMetadata;

fn idp_roles_sharing_an_index(extra_service: &str) -> String {
    let service = |location: &str, index: u16| {
        format!(
            r#"<md:ArtifactResolutionService Binding="{SOAP_BINDING}" Location="{location}" index="{index}"/>"#
        )
    };
    let sso = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>"#;
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">
    {saml11}
    {sso}
  </md:IDPSSODescriptor>
  <md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
    {first}
    {sso}
  </md:IDPSSODescriptor>
  <md:SPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
    {sp}
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/acs" index="0"/>
  </md:SPSSODescriptor>
  <md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
    {second}
    {unique}
    {extra_service}
    {sso}
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        saml11 = service("https://idp.example.com/saml11/artifact", 5),
        first = service(RESOLUTION_URL, 0),
        sp = service("https://idp.example.com/sp/artifact", 5),
        second = service("https://idp.example.com/second/artifact", 0),
        unique = service("https://idp.example.com/second/artifact-5", 5),
    )
}

#[test]
fn a_resolution_index_is_unique_only_within_its_identity_provider_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let at_index = |index: u16| {
        recode(&artifact, |bytes| {
            bytes[2..4].copy_from_slice(&index.to_be_bytes());
        })
    };
    let resolve = |metadata: &str, artifact: &Artifact| -> Result<_, Box<dyn std::error::Error>> {
        let peer = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            metadata,
            MetadataTrustPolicy::Unverified,
        )?;
        Ok(parties
            .sp
            .resolve_artifact(&peer, artifact, confidential(), without_replay_cache()))
    };
    let shared_elsewhere = idp_roles_sharing_an_index("");

    let published: Vec<(u16, String)> = IdpMetadata::from_xml(&shared_elsewhere)?
        .artifact_resolution_services()?
        .into_iter()
        .map(|service| (service.index(), service.location().to_owned()))
        .collect();
    assert_eq!(
        published,
        [
            (0, RESOLUTION_URL.to_owned()),
            (0, "https://idp.example.com/second/artifact".to_owned()),
            (5, "https://idp.example.com/second/artifact-5".to_owned()),
        ]
    );

    let unique = resolve(&shared_elsewhere, &at_index(5)?)??;
    assert_eq!(
        unique.request().endpoint().as_str(),
        "https://idp.example.com/second/artifact-5"
    );

    let shared = resolve(&shared_elsewhere, &at_index(0)?)?;
    assert!(
        matches!(
            &shared,
            Err(SamlError::Invalid(detail))
                if detail == "ArtifactResolutionService index 0 is published by more than one IDPSSODescriptor"
        ),
        "{shared:?}"
    );

    let repeated_in_one_role = idp_roles_sharing_an_index(&format!(
        r#"<md:ArtifactResolutionService Binding="{SOAP_BINDING}" Location="https://idp.example.com/second/again" index="5"/>"#
    ));
    let duplicate = resolve(&repeated_in_one_role, &at_index(5)?)?;
    assert!(
        matches!(
            &duplicate,
            Err(SamlError::Invalid(detail)) if detail == "duplicate ArtifactResolutionService index 5"
        ),
        "{duplicate:?}"
    );
    Ok(())
}

#[test]
fn a_blank_resolution_endpoint_refuses_only_the_artifacts_that_name_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let at_index = |index: u16| {
        recode(&artifact, |bytes| {
            bytes[2..4].copy_from_slice(&index.to_be_bytes());
        })
    };
    let peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_roles_sharing_an_index(&format!(
            r#"<md:ArtifactResolutionService Binding="" Location="https://idp.example.com/second/blank-binding" index="7"/>
    <md:ArtifactResolutionService Binding="{SOAP_BINDING}" Location=" &#x9; " index="8"/>"#
        )),
        MetadataTrustPolicy::Unverified,
    )?;
    let resolve = |index: u16| -> Result<_, Box<dyn std::error::Error>> {
        Ok(parties.sp.resolve_artifact(
            &peer,
            &at_index(index)?,
            confidential(),
            without_replay_cache(),
        ))
    };

    let unique = resolve(5)??;
    assert_eq!(
        unique.request().endpoint().as_str(),
        "https://idp.example.com/second/artifact-5"
    );
    let blank_binding = resolve(7)?;
    assert!(
        matches!(&blank_binding, Err(SamlError::Unsupported(_))),
        "{blank_binding:?}"
    );
    let blank_location = resolve(8)?;
    assert!(
        matches!(&blank_location, Err(SamlError::Invalid(_))),
        "{blank_location:?}"
    );
    Ok(())
}
