# Upgrade typed operation options, PAOS, and name identifier management code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet` that set SSO, Single Logout, or name identifier management options,
run Enhanced Client/Proxy login over PAOS, manage name identifiers over SOAP,
or build the Identity Provider Discovery cookie. Apply the sections that match
your integration.

## Rename the shared option setters

**Affects:** callers of the setters in the table below.

**Before:** each flow named the same option after itself, and the passive
setter used the `is_` prefix of a `bool` getter.

**Now:** one name per option. The setters do what they did before.

| Before | After |
| --- | --- |
| `StartSso::is_passive(value)`, `StartPaosSso::is_passive(value)` | `passive(value)` |
| `StartSso::assertion_consumer_service_index(index)` | `StartSso::acs_index(index)` |
| `StartSso::apply_web_browser_sso_generation_rules()`, `RespondSso::apply_web_browser_sso_generation_rules()` | `apply_producer_rules()` |
| `StartSlo::apply_single_logout_generation_rules()`, `RespondSlo::apply_single_logout_generation_rules()` | `apply_producer_rules()` |
| `StartSlo::allow_http_single_logout()`, `RespondSlo::allow_http_single_logout()` | `allow_http()` |
| `allow_http_name_id_management()` on `StartNameIdManagement`, `ReceiveNameIdManagement`, or `RespondNameIdManagement` | `allow_http()` |

The getters use the same names. `AuthnRequest::acs_index()` is unchanged, and
`AuthnRequest::is_passive()` is renamed `passive()`, as
[Read audiences per restriction and call the renamed accessors](sso-results-and-identities.md#read-audiences-per-restriction-and-call-the-renamed-accessors)
shows.

The `SamlError::ProtocolProfile` that an `http` peer endpoint returns now names
`allow_http` in its message. Match the variant, not the message.

**Upgrade:** rename each call.

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

## Start PAOS login with `StartPaosSso::new`

**Affects:** service providers that call `StartPaosSso::to_soap_endpoint`,
`StartPaosSso::acs_url`, or `StartPaosSso::provider_name`.

**Before:** `to_soap_endpoint(url)` and `acs_url(url)` took a string and
returned a `Result`. `provider_name(name)` returned a `Result`, and rejected an
empty name and a character XML 1.0 forbids.

**Now:** every `StartPaosSso` setter returns `Self`:

- `StartPaosSso::new(soap_endpoint)` and `acs_url(url)` take an
  `EndpointUrl`. `EndpointUrl::try_new` returns the error the old methods
  returned for a URL that is not an absolute HTTP or HTTPS URL.
- `start_paos_sso` checks `provider_name` with the rule `start_sso` applies to
  `StartSso::provider_name`. A character XML 1.0 forbids returns
  `SamlError::Invalid` from `start_paos_sso`, not from the setter.
- An empty name is accepted and sent as `ProviderName=""`. The ECP schema
  types `ProviderName` as `xs:string`, which allows it.

**Upgrade:**

```rust,ignore
// Before
let options = StartPaosSso::to_soap_endpoint("https://idp.example.com/soap")?
	.acs_url("https://sp.example.com/acs")?
	.provider_name("Example SP")?;

// After
let options = StartPaosSso::new(EndpointUrl::try_new("https://idp.example.com/soap")?)
	.acs_url(EndpointUrl::try_new("https://sp.example.com/acs")?)
	.provider_name("Example SP");
```

If you relied on the setter to refuse an empty name, check the name before you
set it.

## Check the enhanced client headers with `check_paos_client_headers`

**Affects:** service providers that use `PaosClientRequest` or call
`start_paos_sso`.

**Before:** `start_paos_sso(idp, client, options)` took a `PaosClientRequest`,
built with `PaosClientRequest::from_headers(accept, paos)` or
`PaosClientRequest::headers_checked_by_caller()`. The value carried no data,
and `start_paos_sso` did not read it.

**Now:** `PaosClientRequest` is removed, with its `ACCEPT` and `PAOS_HEADER`
constants. `start_paos_sso(idp, options)` takes no client argument and does not
read HTTP headers. `check_paos_client_headers(accept, paos)` runs the checks
`from_headers` ran and returns the same `SamlError::ProtocolProfile`. The
profile obliges the enhanced client to send these headers. The service
provider may check them, or tell an enhanced client apart by other means.

**Upgrade:** call `check_paos_client_headers` where you called `from_headers`,
and drop the client argument.

```rust,ignore
// Before
let client = PaosClientRequest::from_headers(accept, paos)?;
let started = sp.start_paos_sso(&idp, client, options)?;

// After
check_paos_client_headers(accept, paos)?;
let started = sp.start_paos_sso(&idp, options)?;
```

If you sent `PaosClientRequest::ACCEPT` or `PaosClientRequest::PAOS_HEADER`,
write the values. `ACCEPT` was `application/vnd.paos+xml`, and `PAOS_HEADER`
was `ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"`.

## Pass the SOAP envelope to `receive_paos_sso` and `finish_paos_sso`

**Affects:** callers of `PaosAuthnRequest::from_envelope`,
`PaosSsoResponse::from_envelope`, `receive_paos_sso`, `finish_paos_sso`, or
`finish_paos_sso_with_outstanding_logout`.

**Before:** `PaosAuthnRequest` held the request envelope and the URL that
received it. `PaosSsoResponse` held the response envelope. Their constructors
returned `SamlError::Invalid` for an empty or blank envelope.

**Now:** both types are removed. The operations take the envelope as `&str`,
as `receive_name_id_management` and `answer_artifact_resolve` do:

- `receive_paos_sso(sp, request_envelope, soap_endpoint, validation)` takes
  the receiving URL as `&EndpointUrl`.
- `finish_paos_sso(idp, pending, response_envelope, validation)` and
  `finish_paos_sso_with_outstanding_logout(idp, pending, response_envelope,
  validation, outstanding_logout)` take the envelope.
- An empty or blank envelope returns `SamlError::Xml` from the SOAP reader.
  One larger than `XmlLimits::max_bytes` returns `SamlError::LimitExceeded`,
  as any other envelope of that size does.

**Upgrade:**

```rust,ignore
// Before, at the identity provider
let request = idp.receive_paos_sso(
	&sp_descriptor,
	&PaosAuthnRequest::from_envelope(request_envelope, "https://idp.example.com/soap")?,
	validation,
)?;
// Before, at the service provider
let session = sp.finish_paos_sso(
	&idp_descriptor,
	&pending,
	&PaosSsoResponse::from_envelope(response_envelope)?,
	validation,
)?;

// After, at the identity provider
let soap_endpoint = EndpointUrl::try_new("https://idp.example.com/soap")?;
let request = idp.receive_paos_sso(&sp_descriptor, &request_envelope, &soap_endpoint, validation)?;
// After, at the service provider
let session = sp.finish_paos_sso(&idp_descriptor, &pending, &response_envelope, validation)?;
```

If you matched `SamlError::Invalid` for an empty envelope, match
`SamlError::Xml`.

## Answer PAOS login with an `SsoOutcome`

**Affects:** identity providers that call `respond_paos_sso`,
`reject_paos_sso`, or `RespondPaosSso`.

**Before:** `respond_paos_sso(sp, request, subject, options)` took a `Subject`
and `RespondPaosSso` options with the assertion's `attributes`,
`authn_context`, and `authn_instant`, and answered with an assertion.
`reject_paos_sso(sp, request, status)` answered with an error status and no
assertion.

**Now:** `respond_paos_sso(sp, request, outcome)` takes the
`impl Into<SsoOutcome>` that `respond_sso` takes, as
[Answer with an `SsoAssertion` or an `SsoOutcome`](sso-results-and-identities.md#answer-with-an-ssoassertion-or-an-ssooutcome)
describes:

- `SsoAssertion::new(name_id)` answers as `respond_paos_sso` did. It takes the
  `NameId` by value. Clone a `NameId` you only borrow.
- `RespondPaosSso::attributes`, `authn_context`, and `authn_instant` become
  `SsoAssertion::with_attributes`, `with_authn_context`, and
  `with_authn_instant`.
- `SsoOutcome::Failure(status)` answers as `reject_paos_sso` did: HTTP 200 and
  no assertion. A top-level `Success` status returns `SamlError::Invalid`, as
  `reject_paos_sso` did, because a success response needs an assertion.
- `RespondPaosSso` and `reject_paos_sso` are removed.

**Upgrade:**

```rust,ignore
// Before
let ok = idp.respond_paos_sso(
	&sp,
	&request,
	Subject::new(name_id, Vec::new()),
	RespondPaosSso::default().attributes(attributes),
)?;
let denied = idp.reject_paos_sso(&sp, &request, Status::responder())?;

// After
let ok = idp.respond_paos_sso(&sp, &request, SsoAssertion::new(name_id).with_attributes(attributes))?;
let denied = idp.respond_paos_sso(&sp, &request, SsoOutcome::Failure(Status::responder()))?;
```

## Build the SOAP fault with `PaosHttpResponse::soap_fault`

**Affects:** identity providers that call `Saml<Idp>::paos_soap_fault`.

**Before:** `idp.paos_soap_fault()` returned the fault and did not read the
facade.

**Now:** the fault is built by the type that holds it:
`PaosHttpResponse::soap_fault()`. It is the same HTTP 500 SOAP `Client` fault.

**Upgrade:** replace `idp.paos_soap_fault()` with
`PaosHttpResponse::soap_fault()`.

## Build the discovery cookie with `common_domain_cookie`

**Affects:** identity providers that call
`Saml<Idp>::remember_identity_provider`.

**Before:** the method name said it remembered the identity provider, but it
only built the cookie value.

**Now:** the method is `Saml<Idp>::common_domain_cookie`, named for the
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
