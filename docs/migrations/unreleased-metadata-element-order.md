# Update metadata element orders

This change is unreleased.

This guide applies to `SpConfigBuilder::elements_order`,
`IdpConfigBuilder::elements_order`, and the `elements_order` field of the raw
metadata generation configs, including through the compatibility crates.

## Remove unknown and duplicate group names

Generation and typed `build()` now return `SamlError::Invalid` when an order
contains an unknown name or repeats a group. Previously, generation silently
ignored unknown names and wrote repeated groups again.

Correct spelling and use each group name once. SP orders accept
`KeyDescriptor`, `SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`,
and `AssertionConsumerService`. The `AttributeConsumingService` slot remains
accepted for the existing Shibboleth profile, but writes nothing because the
generator has no configuration for it.

IdP orders accept `KeyDescriptor`, `ArtifactResolutionService`,
`SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`, and
`SingleSignOnService`.

Remove `Organization` and `ContactPerson` from the order. Configure those
entity-level elements with `organization` and `contacts`, or the builder's
`organization` and `contact` methods. They still follow the role descriptor.

## Select published data in the config

An order now controls placement, including when it is empty. It no longer
filters configured groups. Missing groups are inserted before the first
listed group that follows them in the metadata schema, or at the end if
there is none. Explicitly listed groups keep their relative order.

For example, with a signing certificate, logout endpoint, NameID format,
and ACS configured, `elements_order = ["AssertionConsumerService"]`
previously wrote only the ACS. It now writes `KeyDescriptor`,
`SingleLogoutService`, `NameIDFormat`, and `AssertionConsumerService`.
SP generation also keeps its default email-address NameID format when the
order does not mention `NameIDFormat`.

To omit optional data, remove it from the metadata config or credentials
instead of leaving its group out of the order. Do not remove a credential
that your signing or decryption policy requires. If you need a separately
curated document, generate it with a separate raw metadata config.

Default profiles retain their output. Explicit non-schema compatibility
orders, including ONELOGIN, retain their relative order and can still produce
schema-invalid metadata. Use the default order for the schema sequence.
