# Read metadata endpoints only in the metadata namespace

This change affects code that imports peer metadata with
`metadata::SpMetadata`, `metadata::IdpMetadata`, `metadata::Metadata::parse`,
or a federation aggregate. No code fails to compile.

saml-rs now reads an `AssertionConsumerService`, `SingleSignOnService`,
`SingleLogoutService`, `ManageNameIDService`, or `ArtifactResolutionService`
only when the element is in the SAML metadata namespace,
`urn:oasis:names:tc:SAML:2.0:metadata`. Before, an element with the same local
name in another namespace was read as an endpoint. For example,
`ext:AssertionConsumerService` in an `md:SPSSODescriptor` could become the
default assertion consumer service.

The metadata schema declares these endpoints in the metadata namespace, so
metadata that passes schema validation does not change. If a peer publishes an
endpoint in another namespace, saml-rs no longer sends messages to it, and a
lookup that found only that endpoint now finds none. Ask the peer to publish
the endpoint in the metadata namespace.
