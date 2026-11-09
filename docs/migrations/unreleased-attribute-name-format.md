# Attribute name formats and persistent and transient NameID length

This change is unreleased. It applies to the release that first publishes
`AttributeNameFormat`.

No signature changes. Two values that were always empty now carry what the
identity provider sent, and an identity provider no longer issues an over-long
persistent or transient `NameID`.

## Compare an accepted attribute with its name format

Who must change: code that compares an `Attribute` from
`SsoSession::attributes` with one it builds, using `==`.

`Attribute::name_format` was `None` on every accepted attribute. It is now the
`NameFormat` URI of the `<Attribute>`, and `None` only when that element has
no `NameFormat`. An attribute built with `Attribute::new(name, None, values)`
is therefore no longer equal to an accepted attribute that has a format.

Build the expected value with its format, or compare the name and the values:

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue};

let expected = Attribute::with_name_format(
    "mail",
    AttributeNameFormat::Basic,
    vec![AttributeValue::new("alice@example.com")],
);
```

`Attributes::get`, `Attribute::name`, and `Attribute::values` return what they
returned before.

## Expect a new key in the raw login response extract

Who must change: code that compares the whole `FlowResult::extract` of a raw
login response, or that iterates over all of its keys.

The extract gains `attributeNameFormats`: the `Name` and `NameFormat` of each
`<Attribute>`, in document order. Existing keys are unchanged.

## Keep persistent and transient NameID values within 256 characters

Who must change: identity provider code that issues a persistent or transient
`NameID` longer than 256 characters. That covers `NameId::new` with
`NameIdFormat::Persistent` or `NameIdFormat::Transient`, a `NameId` without a
format when the identity provider's first configured NameID format is one of
those two, and a raw `User::name_id` in the same cases. SAML Core §8.3.7 and
§8.3.8 forbid such values.

`respond_sso`, `initiate_sso`, `respond_paos_sso`, and the raw
`create_login_response` now return `SamlError::Invalid` for that `NameID`
instead of issuing the response. The limit counts characters, not bytes. A raw
`LoginResponseOptions::custom` callback writes its own `<NameID>` and is not
checked. Service providers still accept a longer value from a peer.

Issue a shorter identifier. `NameId::generate_persistent` and
`NameId::generate_transient` return 41 characters:

```rust
use saml_rs::{NameId, Subject};

let subject = Subject::new(NameId::generate_transient(), Vec::new());
```
