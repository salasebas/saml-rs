# Generated IDs are 160 random bits in 41 characters

This break is unreleased. It applies to `entity::generate_id` and to every
`ID` the crate generates.

A generated `ID` was `_` followed by a version 4 UUID, 37 characters such as
`_332cc680-eda9-429e-be7b-66721ca5502d`. It is now `_` followed by 40
lowercase hexadecimal digits, 41 characters such as
`_3f2a9c0e7b1d4a6f8e2c5b0d9a7f1e3c6b8d2a4f`. The old value carried 122 random
bits, below the 2^-128 collision bound of SAML Core §1.3.4.

The new shape reaches the `ID` of every generated request, response, and
assertion, `BindingContext::id`, the `InResponseTo` a peer sends back, and the
`SessionIndex` an identity provider writes, which is the assertion `ID`.
`NameId::generate_transient` and `NameId::generate_persistent` already used it.

Who must change: callers that parse a generated `ID` or `SessionIndex` as a
UUID, match on its shape, or store it in a column or buffer shorter than 41
characters.

Treat these values as opaque strings. Widen storage to at least 41
characters, and remove UUID parsing. An `ID` you supply yourself, through a
template or a logout `message_id`, is unchanged.
