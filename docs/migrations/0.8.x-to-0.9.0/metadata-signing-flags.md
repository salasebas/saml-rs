# Correct metadata signing flags

[How to upgrade from 0.8 to 0.9](README.md)

If you import SP or IdP metadata, check the unqualified `AuthnRequestsSigned`,
`WantAssertionsSigned`, and `WantAuthnRequestsSigned` attributes on the
peer's SAML 2.0 role. The importers used to treat invalid values as false.
They now return `SamlError::Invalid` for an invalid value, even without a
schema validator.

Earlier versions could read a prefixed attribute as a signing flag. The
importers now reject signing flags qualified with the SAML metadata namespace
and ignore attributes from other namespaces when reading signing flags. If
the unqualified signing flag is absent, it defaults to false.

Ask the metadata publisher to publish the signing flags without a prefix.
Use `true` or `1` for true, and `false` or `0` for false. If the metadata is
signed, ask the publisher to sign the corrected document before you import it.
