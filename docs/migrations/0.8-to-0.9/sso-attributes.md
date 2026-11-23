# Update SSO attributes

[How to upgrade from 0.8 to 0.9](README.md)

## 4. Give each login response template attribute a value

**Affects:** identity providers that set `LoginResponseTemplate::attributes`
together with a custom `LoginResponseTemplate::context`.

**Before:** an attribute with no value kept its `{attr<Tag>}` placeholder,
such as `{attrEmail}`, and the identity provider signed the response with that
text as the attribute value. Without a custom `context`, the built-in renderer
already returned an error for the same configuration.

**Now:** the raw API that read `LoginResponseTemplate::attributes` is removed.
A typed identity provider has no template attributes.
Use the [typed SSO inputs](config.md#replace-sso-templates-with-typed-options).

**Upgrade:** pass the attributes with `SsoAssertion::with_attributes`, as
[2.2](public-imports.md#22-pass-attributes-to-the-response) shows.

## 5. Send a `Name` on every attribute

**Affects:** service providers whose identity provider sends an `<Attribute>`
without a `Name`. This applies to `finish_sso`,
`finish_sso_with_outstanding_logout`, `accept_unsolicited_sso`, and
`accept_unsolicited_sso_with_outstanding_logout`, with every validation preset.

**Before:** the session accepted the attribute under the name `""`. Every
`<Attribute>` without a `Name` and with the same `NameFormat` merged into that
one attribute.

**Now:** the operation returns `SamlError::ProtocolProfile` with
`Attribute is missing required unqualified attribute Name`. The assertion
schema requires `Name` on `<Attribute>`. An `<Attribute Name="">` is still
accepted as the attribute `""`.

**Upgrade:** configure the identity provider to write a `Name` on each
attribute it releases.

## 6. Send `subject-id` and `pairwise-id` in the profile's form

**Affects:** identity providers that pass an attribute named
`urn:oasis:names:tc:SAML:attribute:subject-id` or
`urn:oasis:names:tc:SAML:attribute:pairwise-id`, with the `uri` name format,
the unspecified one, or none, to `SsoAssertion::with_attributes`.

**Before:** the identity provider wrote the attribute as given, with
`xsi:type="xs:string"` on each value.

**Now:** `respond_sso`, `initiate_sso`, `respond_sso_artifact`, and
`initiate_sso_artifact` return `SamlError::Invalid`
when the attribute has the unspecified name format or none, when it has no
value or several values, when the assertion has it twice in any of those name
formats, when the value is not `uniqueID@scope`, when the scope has an upper
case letter, or when the unique ID has both upper and lower case letters. The
value is written without `xsi:type`. An attribute with one of these names and
another name format is written as before.

**Upgrade:** create the value with `SubjectId::try_new` or
`PairwiseId::try_new` and add it with `Attribute::from`. Write the scope in
lower case, and the unique ID in one case.

If the service provider reads these attributes as identifiers, call
`SsoSession::subject_id()` or `SsoSession::pairwise_id()`. Each returns
`Ok(None)` when the attribute is absent and `SamlError::ProtocolProfile`
when the corresponding identifier is malformed. Check which scopes the
issuer is authorized to assert before using the identifier to select an
account.

## Compare attributes that carry a `FriendlyName`

The SP now preserves `FriendlyName` on received attributes. If you compare
an entire received `Attribute` with one your application constructs, the
comparison includes that field. Set the expected label with
`Attribute::with_friendly_name` or compare the name, format, and values
your application uses.

When several elements share the same name and format, their values still
merge. The merged attribute keeps the first element's `FriendlyName`.
