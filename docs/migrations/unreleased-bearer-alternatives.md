# Handle SSO responses with alternative assertions and confirmations

The service provider now judges a Web SSO response by the assertion that
`SsoSession` reads, tries each bearer confirmation of an unsolicited
response, and compares every received `InResponseTo` after XML whitespace
collapse. No method signature changes. Update code that matches the errors
below, and tests that expect these responses to be rejected.

## Expect other assertions to be discarded

`finish_sso`, `accept_unsolicited_sso`, and their `_with_outstanding_logout`
and `_with_resolver` variants read one assertion: the first bearer assertion
with an `AuthnStatement`, or else the first bearer assertion. That assertion
must pass every check, as before.

Another assertion in the same response no longer rejects it when its own
bearer confirmation, `AudienceRestriction`, `Conditions` children or window,
or `SessionNotOnOrAfter` fails. Before, the response returned
`SamlError::SubjectConfirmationInvalid`, `SamlError::AudienceMismatch`,
`SamlError::UnrecognizedCondition`, or `SamlError::TimeWindowInvalid`. The
session never contained data from that assertion, and it still does not.

Each assertion must still name the same issuer and principal, and each
signature must still verify. With `ReplayPolicy::RequireCache`, the cache
still stores the identifier of every other assertion, except one whose latest
bearer `NotOnOrAfter` has passed or does not parse. No later response can
confirm such an assertion.

## Match the new error for a bearer `InResponseTo` on an unsolicited response

On `accept_unsolicited_sso`, a bearer `SubjectConfirmationData` that carries
`InResponseTo`, even an empty one, now leaves only its own confirmation
unsatisfied. The response is accepted when another bearer confirmation of the
assertion is satisfied. Otherwise, the result is
`SamlError::SubjectConfirmationInvalid` with
`SubjectConfirmationReason::InResponseToMismatch`, the error that `finish_sso`
returns for a bearer `InResponseTo` that does not match. An `InResponseTo` on
the `Response` still returns `SamlError::InResponseToMismatch`.

Before:

```rust
Err(SamlError::InResponseToMismatch { expected: None, .. }) => reject_as_solicited(),
```

After:

```rust
Err(SamlError::InResponseToMismatch { expected: None, .. })
| Err(SamlError::SubjectConfirmationInvalid {
    reason: SubjectConfirmationReason::InResponseToMismatch,
}) => reject_as_solicited(),
```

## Expect padded `InResponseTo` values to match

A received `InResponseTo` is an `xs:NCName`, so saml-rs now removes the
surrounding XML whitespace before it compares the value with the pending
request ID. This applies to the SSO `Response` and its bearer confirmations,
SSO error responses and their status message, `LogoutResponse` and
`ManageNameIDResponse` on every binding, and SOAP `ArtifactResponse`
messages. A response whose value differed from the request ID only by that
whitespace is now accepted. Before, it returned
`SamlError::InResponseToMismatch` or `SamlError::SubjectConfirmationInvalid`.

`SsoSession::in_response_to` and `LogoutResponse::in_response_to` return the
value without the whitespace.
