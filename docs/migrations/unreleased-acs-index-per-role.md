# Select assertion consumer services within one SP role

These changes affect an identity provider that imports service provider
metadata with more than one SAML 2.0 `SPSSODescriptor` in one entity. Metadata
with a single SAML 2.0 SP role behaves as before. No code fails to compile.

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
request without a binding still goes to the default of the first SAML 2.0 SP
role.

If a service provider expects responses at the `isDefault="true"` endpoint of
a later role, ask it to mark that endpoint as the default in its first role,
or to send `AssertionConsumerServiceURL` or `AssertionConsumerServiceIndex`.

## Shared ACS index

An `AssertionConsumerServiceIndex` that more than one SAML 2.0 SP role
publishes is still refused with `SamlError::Invalid`, because the request does
not name the role. The message now reads
`AssertionConsumerService index 0 is published by more than one SPSSODescriptor`
instead of `duplicate AssertionConsumerService index 0`. An index that one role
publishes twice keeps the `duplicate` message. Match the variant, not the
message.
