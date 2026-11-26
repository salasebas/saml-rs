# Update API callers

[How to upgrade from 0.6 to 0.7](README.md)

## Fix compilation errors

### Extend exhaustive matches

Add arms for these new variants where you match the corresponding enum:

| Enum | Add arms for |
| --- | --- |
| `SsoResponseBinding` | `Artifact` |
| `BrowserInput` | `Artifact`, `Soap { envelope, channel, .. }` |
| `LogoutBinding` | `Soap` |
| `saml_rs::constants::Binding`, also exported through `raw` | `Soap` |
| `saml_rs::constants::ParserType` | `ManageNameIdRequest`, `ManageNameIdResponse` |
| `SignatureAlgorithm` | `RsaSha1`, `DsaSha1`, `HmacSha1` |
| `TransformAlgorithm` | `CanonicalXml` |

Use `BrowserInput::<SsoResponse>::artifact` for artifact input, and `soap`
or `soap_with_channel` on logout input types for SOAP. Raw SSO and logout
creation still reject SOAP with `SamlError::UnsupportedBinding`. Typed
AuthnRequest and logout calls return an error for `BrowserInput::Artifact`.

`Binding::from_urn` now returns `Binding::Soap` for
`urn:oasis:names:tc:SAML:2.0:bindings:SOAP` instead of `None`, so an
`AuthnRequest` whose `ProtocolBinding` is that URN fails with
`SamlError::UndefinedBinding` instead of `SamlError::Invalid`.
`Metadata::get_support_bindings` lists `Binding::Soap` when metadata publishes
a SOAP `SingleLogoutService`, and an identity provider that publishes only
that endpoint now writes `SessionIndex` in its assertions.

### Complete struct literals

If you list every field in these structs, add the new fields:

- On `Credentials`, raw `EntitySetting`, and raw `FlowOptions`, add `hmac_secret: None` when you do not use HMAC.
- On typed and raw `IdpMetadataConfig`, add `artifact_resolution_service: Vec::new()` when you do not publish artifact resolution.
- On typed and raw `SpMetadataConfig` and `IdpMetadataConfig`, add `manage_name_id_service: Vec::new()` when you do not publish name identifier management.

Existing metadata constructors supply empty lists. Use
`..Default::default()` where the struct supports it.

### Handle metadata generation errors

Handle the new `Result<String, SamlError>` from
`saml_rs::metadata::generate_sp_metadata` and `generate_idp_metadata`, for
example with `?`. Invalid NameID formats return `SamlError::Invalid`.
`try_generate_idp_metadata`, `Saml::sp`, and `Saml::idp` return the same
error for an invalid configured format.

## Update identifiers and comparisons

Use absolute URIs or `NameIdFormat` constants for every format you send.
Replace empty, blank, relative, or malformed values such as `local-format`
with a value such as `urn:example:name-id-format`. Check `NameId`, config
`name_id_format` lists, and raw `EntitySetting::name_id_format`.
Generation now returns `SamlError::Invalid` for invalid formats, including
when you send a received NameID back through logout or name identifier management.

To leave the format unspecified, use `NameId::new(value, None)` or an empty
format list. A blank list entry is an error. Expect generated assertions,
logout requests, and raw AuthnRequest `NameIDPolicy` to omit `Format`
instead of writing `Format=""`. Treat a session NameID format of `None` as
unspecified instead of expecting `Some(NameIdFormat::Custom(String::new()))`.
Custom callbacks that write their own XML remain responsible for it.

If your IdP issues persistent or transient NameIDs longer than 256 characters,
shorten them to avoid `SamlError::Invalid`. `NameId::generate_persistent`
and `NameId::generate_transient` return 41-character values. Received values
are not subject to this new generation limit.

If you parse generated IDs or session indexes as UUIDs, remove that parsing
and allow at least 41 characters in storage. Generated IDs now contain `_`
followed by 40 lowercase hexadecimal digits. Treat them as opaque strings.
Caller-supplied IDs are unchanged.

Update whole-object comparisons where these fields matter:

- Include the received `Attribute::name_format`, or compare only the attribute name and values. It is no longer always `None`.
- Include the assertion's NameID qualifiers when comparing `SsoSession::name_id()` or `subject()`, or compare only `value()` and `format()`.
- Allow the new `attributeNameFormats` key when comparing or iterating over raw `FlowResult::extract`.
- Account for `identifiers` and `attributes` in `XmlEncryptionPolicy` debug output, including containing configs, and `identifier_encryption` in `StartSlo` debug output.

## Update error handling and encoded input

If you map `SamlError` cases by name, handle these additions:

- Treat `EncryptionRequired { element }` as a rejected response containing plaintext where encryption was required.
- Handle `ArtifactNotReturned` when successful artifact resolution contains no protocol message.
- Handle `SoapChannelProtection` when the attested SOAP channel lacks required protection.

`SamlError` remains `#[non_exhaustive]`, so existing wildcard arms still compile.

If inbound base64 contains Unicode whitespace or vertical tabs, remove it.
`base64_decode_with_limit`, used by Redirect, POST, and SimpleSign reception,
now ignores only space, tab, CR, LF, and form feed. Other non-alphabet bytes
are rejected. `base64_decode` is unchanged.
