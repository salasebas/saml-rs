# Metadata signing flags read `1` as true

This break is unreleased. It applies to metadata whose `WantAuthnRequestsSigned`,
`AuthnRequestsSigned`, or `WantAssertionsSigned` is `1`, or a boolean with
surrounding whitespace.

These attributes are XML Schema booleans, so `1` is now true and `0` is false,
as `true` and `false` already were. Before, only `true` was true.

Who must change: providers built from such metadata, raw or typed.

- An identity provider whose own metadata sets `WantAuthnRequestsSigned="1"`
  returns `SamlError::SignatureMissing` for an unsigned AuthnRequest.
- A service provider whose own metadata sets `AuthnRequestsSigned="1"` signs
  its AuthnRequests, so it needs a signing key.
- `start_sso` returns `ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG` when one side
  of the SP and IdP metadata is now true and the other is false.
- A service provider whose metadata sets `WantAssertionsSigned="1"` receives
  signed assertions and requires them.

Sign the requests the metadata asks for, or publish `false` where the flag was
not meant to be set.
