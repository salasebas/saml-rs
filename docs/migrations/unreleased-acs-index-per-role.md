# Select assertion consumer services within one SP role

These changes affect an identity provider that imports service provider
metadata. Most apply only when one entity has more than one SAML 2.0
`SPSSODescriptor`. No code fails to compile.

## Default for a binding

`IdentityProvider::respond_sso` answers an AuthnRequest that names only a
`ProtocolBinding` at the default endpoint of that binding. It now takes that
default from the first SAML 2.0 `SPSSODescriptor` that publishes an
`AssertionConsumerService` for the binding. Before, it compared the endpoints
of every SAML 2.0 SP role, so an endpoint with `isDefault="true"` in a later
role won over the default of an earlier role. E37 in SAML V2.0 Approved
Errata 05 defines the default within one role.

`SpDescriptor::assertion_consumer_location` and
`metadata::SpMetadata::assertion_consumer_location` use the same rule. A
request with no `AssertionConsumerServiceURL`, `AssertionConsumerServiceIndex`,
or `ProtocolBinding` still goes to the default of the first SAML 2.0 SP role.

If a service provider expects responses at the `isDefault="true"` endpoint of
a later role, ask it to mark that endpoint as the default in its first role.
It can also send `AssertionConsumerServiceURL`, or an
`AssertionConsumerServiceIndex` that no other SAML 2.0 SP role publishes.

## Shared or repeated ACS index

An `AssertionConsumerServiceIndex` that more than one SAML 2.0 SP role
publishes is still refused with `SamlError::Invalid`, because the request does
not name the role. The message now reads
`AssertionConsumerService index 0 is published by more than one SPSSODescriptor`
instead of `duplicate AssertionConsumerService index 0`. An index that one role
publishes twice keeps the `duplicate` message. Match the variant, not the
message.

Both checks now count every `AssertionConsumerService` with the index,
including one whose binding saml-rs does not answer, such as PAOS. Before, a
POST endpoint and a PAOS endpoint that shared an index resolved to the POST
endpoint. This also applies to metadata with a single SP role.

If one role repeats the index, ask the service provider to give each endpoint
of that role its own index. If several roles publish it, ask the service
provider to send its `AssertionConsumerServiceURL`, or an
`AssertionConsumerServiceIndex` that only one SAML 2.0 SP role publishes.
