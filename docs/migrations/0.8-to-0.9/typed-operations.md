# Upgrade typed operation options and name identifier management code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet` that set SSO, Single Logout, or name identifier management options,
manage name identifiers over SOAP, or build the Identity Provider Discovery
cookie. Apply the sections that match your integration. Enhanced Client/Proxy
login is removed, as [Remove Enhanced Client/Proxy SSO](ecp-removal.md) says.

## Rename the shared option setters

**Affects:** callers of the setters in the table below.

**Before:** each flow named the same option after itself, and the passive
setter used the `is_` prefix of a `bool` getter.

**Now:** one name per option. Producer rules now apply to every call.

| Before | After |
| --- | --- |
| `StartSso::is_passive(value)` | `passive(value)` |
| `StartSso::assertion_consumer_service_index(index)` | `StartSso::acs_index(index)` |
| `StartSso::apply_web_browser_sso_generation_rules()`, `RespondSso::apply_web_browser_sso_generation_rules()` | Remove the call. All bindings enforce the producer rules. |
| `StartSlo::apply_single_logout_generation_rules()`, `RespondSlo::apply_single_logout_generation_rules()` | Remove the call. All bindings enforce the producer rules. |
| `StartSlo::allow_http_single_logout()`, `RespondSlo::allow_http_single_logout()` | `allow_http()` |
| `allow_http_name_id_management()` on `StartNameIdManagement`, `ReceiveNameIdManagement`, or `RespondNameIdManagement` | `allow_http()` |

The getters use the same names. `AuthnRequest::acs_index()` is unchanged, and
`AuthnRequest::is_passive()` is renamed `passive()`, as
[Read audiences per restriction and call the renamed accessors](sso-results-and-identities.md#read-audiences-per-restriction-and-call-the-renamed-accessors)
shows.

The `SamlError::ProtocolProfile` that an `http` peer endpoint returns now names
`allow_http` in its message. Match the variant, not the message.

**Upgrade:** replace or remove each call as shown in the table.

## Generate SSO and Single Logout messages

**Affects:** callers that start or respond to SSO or Single Logout.

**Before:** callers opted in to the generation rules on individual messages and
could select unsigned logout requests.

**Now:** a transient AuthnRequest omits `AllowCreate`. Each successful browser
SSO response includes an `AuthnStatement` and includes a session index when the
IdP advertises Single Logout. The IdP returns `SamlError::Invalid` if the
assertion fails an exact `RequestedAuthnContext`, omits or changes a required
`SPNameQualifier`, or fails the strong match for a requested subject identifier. The authentication
context defaults to the `unspecified` class.

Both roles sign logout requests. An SP returns `SamlError::ProtocolProfile` if
it starts logout without a session index or sends a browser logout request or
response to an HTTP endpoint without selecting `allow_http()`. Custom SP logout
request templates are also checked before signing. A template with an
unexpanded `NotOnOrAfter`, a different NameID format, or a missing requested
qualifier fails with `SamlError::ProtocolProfile`. Preserve the subject and
session indexes supplied by the caller, or use the built-in renderer.

**Upgrade:** remove the producer-rule setters, `StartSlo::signing` and the
`LogoutSigning` import. Supply signing credentials and enable a document-crypto
provider. Pass the actual authentication context with
`SsoAssertion::with_authn_context` and the authentication instant when known.
Issue a failure response when the request cannot be satisfied. Use the session
from SSO to start logout and publish HTTPS endpoints for browser logout.

```rust
# use saml_rs::{IdpDescriptor, ServiceProvider, SsoSession, StartSlo};
# fn start(sp: &ServiceProvider, idp: &IdpDescriptor, session: &SsoSession) -> Result<(), Box<dyn std::error::Error>> {
let subject = session.logout_subject().ok_or("missing logout subject")?;
let started = sp.start_slo(idp, subject, StartSlo::post())?;
# let _ = started;
# Ok(()) }
```

## Build name identifier management options with `new`

**Affects:** callers of `StartNameIdManagement::redirect()`,
`ReceiveNameIdManagement::redirect()`, or `RespondNameIdManagement::redirect()`.

**Before:** the constructors were named for HTTP-Redirect, the only binding
that took these options.

**Now:** each type has `new()` and a `Default` that agrees with it, with the
defaults `redirect()` had. The one exception is the response status:
`RespondNameIdManagement` no longer sets it, as
[Pass the response status to `respond_slo` and `respond_name_id_management_redirect`](#pass-the-response-status-to-respond_slo-and-respond_name_id_management_redirect)
shows. `StartNameIdManagement` works on both bindings, and the operation
chooses the binding: `start_name_id_management` sends over SOAP, and
`start_name_id_management_redirect` sends over HTTP-Redirect.

**Upgrade:** replace `::redirect()` with `::new()`.

```rust,ignore
// Before
let started = sp.start_name_id_management_redirect(
	&idp,
	&name_id,
	&NameIdChange::NewId("alias-42".into()),
	StartNameIdManagement::redirect(),
)?;

// After
let started = sp.start_name_id_management_redirect(
	&idp,
	&name_id,
	&NameIdChange::NewId("alias-42".into()),
	StartNameIdManagement::new(),
)?;
```

## Pass `StartNameIdManagement` to `start_name_id_management`

**Affects:** identity providers that call `Saml<Idp>::start_name_id_management`.

**Before:** `start_name_id_management` took an `IdentifierEncryptionPolicy`.

**Now:** it takes `StartNameIdManagement`, the options of
`start_name_id_management_redirect`:

- `StartNameIdManagement::new()` sends `NameID` and `NewID` in plaintext, as
  `IdentifierEncryptionPolicy::PlaintextIdentifiers` did. To encrypt them,
  call `identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers)`.
- A SOAP request carries no RelayState. `start_name_id_management` returns
  `SamlError::ProtocolProfile` when `StartNameIdManagement::relay_state` is
  set, as `start_slo` does for `StartSlo::soap()`.
- `StartNameIdManagement::allow_http()` has no effect over SOAP. The
  deployment sends the request itself.

`receive_name_id_management` and `respond_name_id_management` take the same
arguments as before. [Match `NameIdManagementReceipt`](#match-nameidmanagementreceipt)
covers the renamed return type of `receive_name_id_management`.

**Upgrade:**

```rust,ignore
// Before
let started = idp.start_name_id_management(
	&sp,
	&current,
	&NameIdChange::Terminate,
	IdentifierEncryptionPolicy::EncryptIdentifiers,
	SoapChannel::mutually_authenticated_confidential(),
)?;

// After
let started = idp.start_name_id_management(
	&sp,
	&current,
	&NameIdChange::Terminate,
	StartNameIdManagement::new()
		.identifier_encryption(IdentifierEncryptionPolicy::EncryptIdentifiers),
	SoapChannel::mutually_authenticated_confidential(),
)?;
```

## Pass the response status to `respond_slo` and `respond_name_id_management_redirect`

**Affects:** callers of `respond_slo` or `respond_name_id_management_redirect`
on `Saml<Sp>` or `Saml<Idp>`.

**Before:** `RespondSlo::status` and `RespondNameIdManagement::status` set the
response status. A response built without the setter reported top-level
`Success`, whether or not the logout or the change had happened.

**Now:** both setters are removed. `respond_slo` and
`respond_name_id_management_redirect` take a `&Status` argument after the
request, and the options keep only delivery choices. There is no default
status, so a call that set none must now pass the outcome. `Status::success()`
is the outcome only when it is true:

- A service provider answering `respond_slo` passes `Status::success()` after
  it invalidates the sessions the request names that the identity provider's
  assertions established.
- An identity provider answering `respond_slo` passes `Status::success()`
  after it ends its own session with the principal. If another session
  participant did not confirm its logout, add
  `SubordinateStatusCode::partial_logout()` with `Status::with_subordinate`.
- A provider answering `respond_name_id_management_redirect` passes
  `Status::success()` after it applies the change. For an identifier it does
  not recognize, it passes `Status::requester()` or `Status::responder()`,
  optionally with `SubordinateStatusCode::unknown_principal()`.

In every other case, pass an error status. A logout-response template still
substitutes only the top-level code: `respond_slo` rejects a subordinate code
in `status` when a template is set.

**Upgrade:** move the status from the options to the argument. Where the call
set no status, pass the status that reports what happened.

A logout answered without a status:

```rust,ignore
// Before
let response = idp.respond_slo(&sp, &request, RespondSlo::post())?;

// After
let response = idp.respond_slo(&sp, &request, &Status::success(), RespondSlo::post())?;
```

A logout answered with an error status:

```rust,ignore
// Before
let response = sp.respond_slo(
	&idp,
	&request,
	RespondSlo::redirect().status(Status::responder()),
)?;

// After
let response = sp.respond_slo(&idp, &request, &Status::responder(), RespondSlo::redirect())?;
```

Name identifier management over HTTP-Redirect. The 0.8 options were built
with `RespondNameIdManagement::redirect()`, which is now
`RespondNameIdManagement::new()`, as
[Build name identifier management options with `new`](#build-name-identifier-management-options-with-new)
shows:

```rust,ignore
// Before
let response = sp.respond_name_id_management_redirect(
	&idp,
	&request,
	RespondNameIdManagement::redirect(),
)?;

// After
let status = if !recognizes(request.message().name_id()) {
	Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal())
} else if apply(request.message().change()).is_ok() {
	Status::success()
} else {
	Status::responder()
};
let response = sp.respond_name_id_management_redirect(
	&idp,
	&request,
	&status,
	RespondNameIdManagement::new(),
)?;
```

## Match `NameIdManagementReceipt`

**Affects:** callers that name `ReceivedNameIdManagement` or
`ReceivedNameIdManagementRedirect`.

**Before:** the result of `receive_name_id_management` was
`ReceivedNameIdManagement`, one letter away from the options type
`ReceiveNameIdManagement`. Both often appear in the same `use` and `match`.

**Now:** the result types are renamed. The variants `Request` and `Refused`
are unchanged.

| Before | After |
| --- | --- |
| `ReceivedNameIdManagement` | `NameIdManagementReceipt` |
| `ReceivedNameIdManagementRedirect` | `NameIdManagementRedirectReceipt` |

**Upgrade:** rename the type in each `use`, `match`, and signature.

## Build the discovery cookie with `common_domain_cookie`

**Affects:** identity providers that call
`Saml<Idp>::remember_identity_provider`.

**Before:** the method name said it remembered the identity provider, but it
only built the cookie value.

**Now:** the method is `IdentityProvider::common_domain_cookie`, named for the
`CommonDomainCookie` it returns. It takes the same `RememberIdentityProvider`
options and returns the same errors. You still write the cookie.

**Upgrade:** rename the call.

```rust,ignore
// Before
let cookie = idp.remember_identity_provider(RememberIdentityProvider::new(
	"example.org",
	CommonDomainCookieLifetime::Session,
))?;

// After
let cookie = idp.common_domain_cookie(RememberIdentityProvider::new(
	"example.org",
	CommonDomainCookieLifetime::Session,
))?;
```
