# 4. Identity provider

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Section |
| --- | --- |
| A `Subject` with confirmations is refused | [4.1](#41-issue-a-subject-without-confirmations) |
| An exact `RequestedAuthnContext` must be met | [4.2](#42-state-the-authentication-context-an-exact-request-asks-for) |
| `SPNameQualifier` is read and issued | [4.3](#43-read-and-issue-the-requested-spnamequalifier) |
| A requested `<Subject>` must be issued | [4.4](#44-issue-the-requested-subject) |
| Unsolicited responses omit `InResponseTo` | [4.5](#45-expect-unsolicited-responses-without-inresponseto) |
| Attribute `NameFormat` must be an absolute URI | [4.6](#46-give-each-attribute-an-absolute-nameformat) |
| Padded persistent and transient formats are checked | [4.7](#47-expect-padded-persistent-and-transient-formats-to-be-checked) |
| Tag prefixes must be distinct NCNames | [4.8](#48-choose-valid-distinct-tag-prefixes) |
| Template attribute fields are written literally | [4.9](#49-fill-attribute-names-before-building-the-login-response-template) |

An IdP configured with `DataEncryptionAlgorithm::Custom` naming AES-192-CBC
now signs the outer encrypted Response by default in every login response
method below, as it already does for AES-128-CBC and AES-256-CBC.
`RespondSso::allow_unsigned_encrypted_cbc` preserves the explicit relaxation
except for PAOS. See [the CBC policy change](sp-sso.md#310-sign-cbc-responses-regardless-of-xml-spelling).

The login response methods below are `respond_sso`, `initiate_sso`,
`respond_sso_artifact`, `initiate_sso_artifact`, and `respond_paos_sso`.

## 4.1 Issue a subject without confirmations

**Affects:** identity providers that pass a `Subject` with
`SubjectConfirmation` values to a login response method.

**Before:** the confirmations were dropped and only the library's bearer
confirmation was written, so a holder-of-key confirmation you supplied never
reached the service provider.
**Now:** such a subject returns `SamlError::Unsupported`.

**Upgrade:** build the subject with no confirmations. The response is the one
0.7 sent:

```rust
use saml_rs::{NameId, Subject};

let subject = Subject::new(NameId::new("alice@example.com", None), Vec::new());
```

A proxy that re-issues the subject of an accepted login is affected too,
because that subject carries the upstream bearer confirmation. Keep its
`NameId` and drop the confirmations:

```rust
let subject = Subject::new(session.subject().name_id().clone(), Vec::new());
```

## 4.2 State the authentication context an exact request asks for

**Affects:** `respond_sso` with `apply_web_browser_sso_generation_rules`,
`respond_sso_artifact` under those rules, and `respond_paos_sso`. See
[generation rules](../../conformance/web-browser-sso-generation.md#identity-provider-response).

**Before:** the request's `RequestedAuthnContext` was ignored, and the
response claimed the unspecified class.
**Now:** the typed `AuthnRequest` reads it. When its `Comparison` is `exact`
or omitted, a success response returns `SamlError::Invalid` unless the
authentication context it writes is one of the requested references. Requests
with another comparison, or without `RequestedAuthnContext`, are answered as
before.

**Upgrade:** read `AuthnRequest::requested_authn_context`, then pass the
context the subject was authenticated with:

```rust
let options = RespondSso::post()
    .apply_web_browser_sso_generation_rules()
    .authn_context(AuthnContextReference::class(
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    )?);
```

or, when no requested context can be met, answer with an error status:

```rust
let options = RespondSso::post()
    .status(Status::responder().with_subordinate(SubordinateStatusCode::no_authn_context()));
```

For PAOS, use `RespondPaosSso::authn_context`, or `reject_paos_sso` with the
same status. `RespondSso::authn_context` without
`apply_web_browser_sso_generation_rules` returns `SamlError::Invalid`, because
that response has no `AuthnStatement`.

**Received requests:** `receive_sso` and `receive_paos_sso` now return
`SamlError::Invalid` for a `RequestedAuthnContext` outside its schema: a
`Comparison` other than `exact`, `minimum`, `maximum`, or `better`, no
references, both class and declaration references, or a second
`RequestedAuthnContext`. A namespace-qualified `Comparison`, or a reference in
another namespace, returns `SamlError::ProtocolProfile`; those two also apply
to raw request parsing (`flow`, `parse_login_request`). Before, the element
was not read.

**Raw extract:** `authnContextClassRef` now holds the class references inside
`RequestedAuthnContext`. Before, it read a path that a valid request never
has, and was empty. `requestedAuthnContext`,
`requestedAuthnContextComparison`, and `authnContextDeclRef` are new keys.

## 4.3 Read and issue the requested `SPNameQualifier`

**Affects:** identity providers that receive an `AuthnRequest`, and that issue
a `NameId` through a login response method.

**Received policy.** `AuthnRequest::name_id_policy` after `receive_sso` or
`receive_paos_sso` keeps `SPNameQualifier`, returned by
`NameIdPolicy::sp_name_qualifier`. A `NameIDPolicy` with only
`SPNameQualifier` is now `Some`. Before, it was `None`, as if the request had
no policy. A namespace-qualified `SPNameQualifier` returns
`SamlError::ProtocolProfile` from `receive_sso`, `receive_paos_sso`, and raw
request parsing (`flow`, `parse_login_request`). Before, it was ignored. The
raw `nameIDPolicy` extract carries a `spNameQualifier` key when the attribute
is present.

**Issued `NameID`.** The issued `<NameID>` now carries the `NameQualifier` and
`SPNameQualifier` of the `NameId`. Before, both were dropped. The service
provider reads them back from `SsoSession::name_id`. If you set them only for
your own records, build the `NameId` with `NameId::new` or pass `None` for
them.

**Requested namespace.** A success response to an `AuthnRequest` whose
`NameIDPolicy` has an `SPNameQualifier` and a SAML-defined `Format` other than
`unspecified` or `encrypted` returns `SamlError::Invalid` unless the `NameId`
has that same `SPNameQualifier`. This applies under
`RespondSso::apply_web_browser_sso_generation_rules` and always in
`respond_paos_sso`. Errata 05 E15 requires the two values to be identical.

**Upgrade:** issue an identifier in the requested namespace with that
qualifier, or answer with an error status:

```rust
use saml_rs::constants::status_code;

let requested = received
    .message()
    .name_id_policy()
    .and_then(NameIdPolicy::sp_name_qualifier);
let options = match requested {
    Some(namespace) if !serves_namespace(namespace) => RespondSso::post()
        .apply_web_browser_sso_generation_rules()
        .status(Status::responder().with_subordinate(
            SubordinateStatusCode::try_new(status_code::INVALID_NAME_ID_POLICY)?,
        )),
    Some(_) | None => RespondSso::post().apply_web_browser_sso_generation_rules(),
};
let name_id = NameId::with_qualifiers(
    stored_persistent_value,
    Some(NameIdFormat::Persistent),
    None,
    requested.map(str::to_string),
    None,
);
```

A `NameId` with `NameQualifier` or `SPNameQualifier` and a login response
template returns `SamlError::Invalid`, as `SPProvidedID` already did. Before,
the template dropped them.

## 4.4 Issue the requested subject

**Affects:** identity providers that answer an `AuthnRequest` carrying a
`<Subject>` through `respond_sso` or `respond_sso_artifact` with
`RespondSso::apply_web_browser_sso_generation_rules`, or through
`respond_paos_sso`. See
[Web Browser SSO generation](../../conformance/web-browser-sso-generation.md#identity-provider-response).

**Before:** the library issued any subject.
**Now:** a success response returns `SamlError::Invalid` unless the issued
`NameId` has the value, `Format`, `NameQualifier`, `SPNameQualifier`, and
`SPProvidedID` of the requested `<NameID>`. An omitted `Format` counts as
`unspecified`. A `NameId` in the `NameIDPolicy` `Format`, when that differs
from the requested format, is still issued.

- A requested `<BaseID>` has no success response. Core §3.4.1.4 as amended by
  Errata 05 E75, and Profiles §4.1.4.1, require an error status for an
  unmatched requested subject.
- As library policy, a requested `<EncryptedID>` that was not decrypted has no
  success response either, because the library cannot show the match.

**Upgrade:** issue the requested `NameId` when the authenticated principal is
that subject. Otherwise answer with an error status:

```rust
use saml_rs::constants::status_code;

let identifier = received
    .message()
    .requested_subject()
    .map(RequestedSubject::identifier);
let options = RespondSso::post().apply_web_browser_sso_generation_rules();
let options = match identifier {
    Some(RequestedSubjectIdentifier::NameId(requested)) if !authenticated_as(requested) => options
        .status(Status::responder().with_subordinate(
            SubordinateStatusCode::try_new(status_code::UNKNOWN_PRINCIPAL)?,
        )),
    Some(RequestedSubjectIdentifier::BaseId | RequestedSubjectIdentifier::EncryptedId) => {
        options.status(Status::responder())
    }
    Some(RequestedSubjectIdentifier::NameId(_) | RequestedSubjectIdentifier::NoIdentifier)
    | None => options,
};
```

Answer `respond_paos_sso` the same way with `reject_paos_sso`.

## 4.5 Expect unsolicited responses without `InResponseTo`

**Affects:** identity providers that send unsolicited login responses through
`initiate_sso`, `initiate_sso_artifact`, or the raw `create_login_response`
without `in_response_to`, and login response templates that contain
`InResponseTo="{InResponseTo}"`.

**Before:** samlify-port generation and templates wrote `InResponseTo=""`,
which the schema does not allow.
**Now:** an unsolicited response omits `InResponseTo` on the `Response` and on
the bearer `SubjectConfirmationData`. An `in_response_to` of `Some("")` is
treated as no request. A template element whose text is only `{InResponseTo}`
is removed when there is no request, as `{NameIDFormat}` already is.
Solicited responses are unchanged.

**Upgrade:** update a peer service provider or a test that matched the empty
attribute to expect no `InResponseTo`.

## 4.6 Give each attribute an absolute `NameFormat`

**Affects:** identity providers that send attributes through
`RespondSso::attributes` or `RespondPaosSso::attributes`.

**Before:** any `NameFormat` was written. **Now:** a `NameFormat` that is
blank or not an absolute URI reference, such as `not a uri` or
`/relative/path`, returns `SamlError::Invalid`. Core §1.3.2 requires an
absolute URI.

**Upgrade:** use an `AttributeNameFormat` variant, a deployment URI such as
`https://example.com/attribute-name-format`, or `None` to omit `NameFormat`.

## 4.7 Expect padded persistent and transient formats to be checked

**Affects:** a `NameId` you send, or a NameID format you configure, that is a
`NameIdFormat::Custom` URI naming the persistent or transient format with
surrounding whitespace. Other formats are not affected.

**Now:** the format is compared after the `xs:anyURI` whitespace collapse, as
it already was for the absolute URI check.

| Padded format | Calls | Result now |
| --- | --- | --- |
| Transient | `start_name_id_management`, `start_name_id_management_redirect` | `SamlError::ProtocolProfile` |
| Persistent or transient, value longer than 256 characters | Those two, every login response method, and the raw login response | `SamlError::Invalid` |
| Persistent without qualifiers | `ManageNameIDRequest` generation | Carries the default `NameQualifier` and `SPNameQualifier` |

**Upgrade:** use `NameIdFormat::Persistent` or `NameIdFormat::Transient` to
write the format without padding.

## 4.8 Choose valid, distinct tag prefixes

**Affects:** `tag_prefix_protocol` or `tag_prefix_assertion` set on
`EntitySetting` or `TemplatePolicy`.

**Before:** a prefix such as `1a`, `a,b`, `-x`, `xml`, or `xmlns` was accepted
and produced XML that does not parse, or failed later with another error.
**Now:** each prefix must be an XML NCName other than `xml` and `xmlns`, and
the two must differ. Otherwise generating a login response, a logout request
or response, or a NameID management message returns `SamlError::Invalid`.

A custom login response, logout request, or logout response template is now
rewritten in one pass. With `tag_prefix_protocol = "saml"`, the template's
`samlp:` elements take `saml:`. Before, they were rewritten again to
`tag_prefix_assertion`, and the root declared that prefix twice.

**Upgrade:** pick a prefix that starts with a letter or `_` and contains only
letters, digits, `_`, `-`, or `.`.

## 4.9 Fill attribute names before building the login response template

**Affects:** a `LoginResponseAttribute` field of a login response template that
contains `{`, and direct calls to `attribute_statement_builder`.

**Before:** a `Name` of `role{NameFormat}` or `{NameID}` was filled from
another placeholder, and a `custom` callback could fill its own `{Tenant}`
inside a `Name`.
**Now:** the `Name`, `NameFormat`, `xsi:type`, `xmlns:xs`, and `xmlns:xsi`
text is issued as configured. Each `{` is written as `&#123;`, so no
placeholder pass fills it. Fields without `{` produce the same XML.

**Upgrade:** put the final text in the `LoginResponseAttribute` before you
create the response.
