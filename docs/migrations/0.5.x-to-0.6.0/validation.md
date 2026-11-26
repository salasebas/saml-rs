# Update validation and replay handling

[How to upgrade from 0.5 to 0.6](README.md)

## Rename the CBC response-signature relaxation

This breaks callers that name the old method or the old policy variant.

Who must change: code that calls
`RespondSso::allow_unsigned_encrypted_cbc_for_compatibility`, and code that
names `ResponseSignaturePolicy::AllowUnsignedEncryptedCbcForCompatibility`.

Call the method that allows an unsigned Response around a CBC-encrypted
Assertion:

```rust
RespondSso::post().allow_unsigned_encrypted_cbc();
```

Select the same inbound relaxation with:

```rust
ResponseSignaturePolicy::AllowUnsignedEncryptedCbc
```

Both still relax SAML V2.0 Approved Errata 05 E93 only. They are not the
Compatibility preset.

`SpValidationPolicy::compatibility`, `IdpValidationPolicy::compatibility`,
and `LogoutPolicy::compatibility` keep their names. Compatibility is the
legacy permissive preset: the samlify-port behaviour kept for a caller leaving
the raw API. It does not claim standards conformance.

## Stop sending a condition the service provider does not understand

This breaks a service provider whose identity provider sends a `<Conditions>`
child other than `<AudienceRestriction>`, `<OneTimeUse>`, or
`<ProxyRestriction>`, including `<Condition>`.

Who must change: that integration. `finish_sso` and `accept_unsolicited_sso`
reject the response. There is no switch that turns the check off.

`<OneTimeUse>` and `<ProxyRestriction>` stay valid. The classification is in
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md).

## Accept several assertions that share one issuer and one principal

This breaks a service provider that treated a second `<Assertion>` as a
rejected response.

Who must change: that integration. `finish_sso` and `accept_unsolicited_sso`
accept the response when a signature covers every assertion and the assertions
share one issuer and one principal. There is no switch that restores the
rejection.

The principal comparison is `NameID` value, `Format`, `NameQualifier`, and
`SPNameQualifier`. An omitted `Format` is
`urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. The session comes from
the first assertion with a bearer confirmation. Replay storage keeps every
assertion identifier. The classification is in
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md).

## Allow five minutes of clock skew

A new `SamlValidationContext` allows five minutes of skew on `NotBefore` and
`NotOnOrAfter`. That covers assertion conditions, bearer confirmation,
`AuthnStatement@SessionNotOnOrAfter`, and `LogoutRequest@NotOnOrAfter`.

Who must change: code that calls `SamlValidationContext::new` without
`with_clock_skew` and needs those instants enforced with no tolerance.

Keep zero skew:

```rust
let validation = SamlValidationContext::new(now, replay)
    .with_clock_skew(ClockSkew::strict());
```

If you already set a skew, that value replaces the five minutes.
`ClockSkew::default` stays zero. Raw `clock_drifts` are unchanged.

If `receive_slo` stores a `LogoutRequest` identifier, that deadline is now
`NotOnOrAfter` plus the same skew. The allowance is classified in
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md)
and [Single Logout](../../conformance/single-logout.md).

## Keep bearer assertion identifiers until NotOnOrAfter

Under `ReplayPolicy::RequireCache`, the bearer assertion identifier is
stored until `SubjectConfirmationData@NotOnOrAfter`, plus the context
`NotOnOrAfter` skew. An earlier `Conditions` or `AuthnStatement` instant
does not shorten that identifier. The Response identifier is still stored
and can still expire at the earlier instant.

Who must change: code whose cache drops an assertion identifier at the
`expires_at` passed to `ReplayCache::check_and_store`, and that assumed
that instant was the earliest of `Conditions`, bearer
`SubjectConfirmationData`, and `AuthnStatement`.

`ReplayPolicy::DisabledForCompatibility` still stores nothing. Keep that
hatch:

```rust
let validation = SamlValidationContext::new(
    now,
    ReplayPolicy::DisabledForCompatibility,
);
```

## Add the new validation variants to an exhaustive match

This breaks an exhaustive `match` on `AudienceValidationPolicy` or
`AuthnRequestValidationPolicy`.

Who must change: that `match`. Add
`AudienceValidationPolicy::EvaluatePresentRestrictions` and
`AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent`.

`Default`, `new`, `try_new`, and `compatibility()` still return the 0.5
variants. Config builders still start from `strict()`. `recommended()`
selects the new variants. Match `SkipForCompatibility` and
`AllowUnsignedForCompatibility` by name: inserting the new variants changed
their numeric discriminants.

## Move off `strict()` before the following release

The following release removes `strict()` and points `Default`, `new`,
`try_new`, and the config builders at Recommended together.

Who must change: code that calls `SpValidationPolicy::strict`,
`IdpValidationPolicy::strict`, or `LogoutPolicy::strict`. In that same release,
code that depends on `Default`, `new`, or `try_new` staying on Compatibility
must change, as must code that depends on a config builder staying on the
`strict()` bundle.

Start from `recommended()` and add only the named hardenings you want. A
direct Assertion signature and the RSA-SHA2 XML-DSig profile stay independent
options. Neither is implied by `recommended()`, and `strict()` does not gain
the RSA-SHA2 profile. Set one field, the other, or both:

```rust
let require_assertion_signature = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::recommended()
};

let require_rsa_sha2 = SpValidationPolicy {
    xml_signatures: XmlSignatureProfile::StrictRsaSha2,
    ..SpValidationPolicy::recommended()
};
```

`LogoutPolicy::recommended()` is the replacement for `LogoutPolicy::strict()`.
Both require a signature on logout requests and responses.

`SpValidationPolicy::compatibility`, `IdpValidationPolicy::compatibility`, and
`LogoutPolicy::compatibility` stay available by name. Raw settings defaults
stay unchanged.
