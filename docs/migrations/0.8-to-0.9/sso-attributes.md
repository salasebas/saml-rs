# Update SSO attributes

[How to upgrade from 0.8 to 0.9](README.md)

## 4. Give each login response template attribute a value

**Affects:** identity providers that set `LoginResponseTemplate::attributes`
together with a custom `LoginResponseTemplate::context`.

**Before:** an attribute with no value kept its `{attr<Tag>}` placeholder,
such as `{attrEmail}`, and the identity provider signed the response with that
text as the attribute value. Without a custom `context`, the built-in renderer
already returned an error for the same configuration.

**Now:** both renderers return
``SamlError::Invalid("missing login response attribute value for `email`")``,
naming the attribute's `value_tag`. The typed login response methods
(`respond_sso`, `initiate_sso`, `respond_sso_artifact`,
`initiate_sso_artifact`, and `respond_paos_sso`) give a template no attribute
values, so every configured template attribute returns this error there.

**Upgrade:** with the raw `IdentityProvider::create_login_response`, put a
value for each attribute's `value_tag` in `User::attributes`:

```rust
use saml_rs::entity::User;

let user = User {
    name_id: "alice@example.com".into(),
    attributes: vec![("email".into(), "alice@example.com".into())],
    session_index: None,
};
```

With the typed API, remove `TemplatePolicy::login_response_template` and pass
the attributes with `RespondSso::attributes`, as
[2.2](public-imports.md#22-pass-attributes-to-the-response) shows.

## 5. Send a `Name` on every attribute

**Affects:** service providers whose identity provider sends an `<Attribute>`
without a `Name`. This applies to `finish_sso`,
`finish_sso_with_outstanding_logout`, `accept_unsolicited_sso`,
`accept_unsolicited_sso_with_outstanding_logout`, `finish_paos_sso`, and
`finish_paos_sso_with_outstanding_logout`, with every validation preset.

**Before:** the session accepted the attribute under the name `""`. Every
`<Attribute>` without a `Name` and with the same `NameFormat` merged into that
one attribute.

**Now:** the operation returns `SamlError::ProtocolProfile` with
`Attribute is missing required unqualified attribute Name`. The assertion
schema requires `Name` on `<Attribute>`. An `<Attribute Name="">` is still
accepted as the attribute `""`.

**Upgrade:** configure the identity provider to write a `Name` on each
attribute it releases. The deprecated raw `parse_login_response_with_request_id`
and `parse_unsolicited_login_response` do not reject the response.
