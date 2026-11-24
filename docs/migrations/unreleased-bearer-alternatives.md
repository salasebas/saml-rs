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
`SsoSession` accessors read only the selected assertion.

Each assertion must still name the same issuer and principal, and each
signature must still verify. Two assertions with the same `ID`, compared after
XML whitespace collapse, are now rejected with
`SamlError::PotentialWrappingAttack`. Before, only a response with an embedded
signature was checked. A SimpleSign response signed only through its binding
signature, or an `ID` repeated only after decryption, could give the session
the `AuthnContext` of another assertion.

With `ReplayPolicy::RequireCache`, the cache still stores the identifier of
every other assertion. When its latest bearer `NotOnOrAfter` has passed or does
not parse, it is stored until the replay deadline of the session's assertion.

## Match the new error for a bearer `InResponseTo` on an unsolicited response

On `accept_unsolicited_sso`, a bearer `SubjectConfirmationData` that carries
`InResponseTo`, even an empty one, now leaves only its own confirmation
unsatisfied. The response is accepted when another bearer confirmation of the
selected assertion is satisfied. Otherwise, the result is
`SamlError::SubjectConfirmationInvalid`, as `finish_sso` returns for a bearer
`InResponseTo` that does not match. Its reason is the failure of the last
confirmation checked: `SubjectConfirmationReason::InResponseToMismatch` when
that confirmation failed only on `InResponseTo`. An `InResponseTo` on a
successful `Response` still returns `SamlError::InResponseToMismatch`.

Before:

```rust
Err(SamlError::InResponseToMismatch { expected: None, .. }) => reject_as_solicited(),
```

After:

```rust
Err(SamlError::InResponseToMismatch { expected: None, .. })
| Err(SamlError::SubjectConfirmationInvalid {
    reason: SubjectConfirmationReason::InResponseToMismatch,
    ..
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
value without the whitespace. The service provider reads the SSO `Response`
`ID`, `IssueInstant`, `Destination`, and `InResponseTo`, and the assertion
`ID` and `IssueInstant`, only from unqualified attributes. Both providers do
the same for the `ID`, `IssueInstant`, `Destination`, and `InResponseTo` of a
`LogoutResponse` or `ManageNameIDResponse`, and read a `SubjectConfirmation`
`Method` the same way. Before, a namespace declaration with the same local
name, such as `xmlns:InResponseTo`, could supply the value.
