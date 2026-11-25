# Handle SSO sessions without a NameID

A service provider now accepts a login assertion whose `Subject` has only
`SubjectConfirmation` elements. Identity providers send such assertions when
they identify the person by attributes alone.

`SsoSession::name_id` now returns `Option<&NameId>`. It returns `None` for
such an assertion. Before, `finish_sso`, `finish_sso_with_outstanding_logout`,
`accept_unsolicited_sso`, `accept_unsolicited_sso_with_resolver`, and
`accept_unsolicited_sso_with_outstanding_logout` rejected the response with
`SamlError::Invalid("missing extracted field nameID")`.

Every caller of `SsoSession::name_id` must handle `None`. Identify the
principal from `SsoSession::attributes`, or refuse the login if your
application needs a `NameID`.

Before:

```rust
let name_id = session.name_id().value();
```

After:

```rust
let Some(name_id) = session.name_id() else {
    // Identify the principal from session.attributes(), or refuse the login.
    return Err(AppError::MissingNameId);
};
let name_id = name_id.value();
```

A session without a `NameID` cannot start Single Logout.
`SsoSession::logout_subject` returns `None` for it, and an `OutstandingLogout`
does not reject it.

Two other subjects are still rejected, with a different error:

- A `Subject` that names the principal with a `BaseID` returns
  `SamlError::Unsupported`. Before, it returned `SamlError::Invalid`.
- A `Subject` whose `EncryptedID` was not decrypted, for example because the
  service provider has no decryption key, returns `SamlError::Unsupported`.
  Before, it returned `SamlError::Invalid`.

If you match `SamlError::Invalid` for these subjects, match
`SamlError::Unsupported` instead.
