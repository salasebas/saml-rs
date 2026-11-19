# Match typed `SamlError` variants

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** code that matches `SamlError` variants or compares error text,
code that converts `base64::DecodeError` or `std::io::Error` into `SamlError`
with `?`, and `ReplayCache` implementations. Code that only propagates
`SamlError` still compiles, but its log text changed: the `ERR_*` codes are
gone.

| You use | What changed | Section |
| --- | --- | --- |
| `StatusNotSuccess { top, second }` | Carries `status: Status` | [Read the status](#read-the-status-from-statusnotsuccess) |
| `ReplayDetected { key }` with `key: String` | `key` is a `ReplayKey` | [Read the replay key](#read-the-replay-key-from-replaydetected) |
| A `ReplayCache` that returns `Invalid` | Return `ReplayCacheUnavailable` | [Report cache failures](#report-replay-cache-failures-with-replaycacheunavailable) |
| `Invalid(message)` or `Xml(message)` compared with an `ERR_*` code or a fixed message | A typed variant | [Match the new variants](#match-the-new-variants-instead-of-message-text) |
| `UndefinedBinding`, `UndefinedStatus` | Removed or renamed | [Replace the binding and status variants](#replace-the-binding-and-status-variants) |
| `SignatureVerificationReason::DetachedMessageSignature` | Renamed `BindingSignature` | [Match `BindingSignature`](#match-bindingsignature) |
| `Xml(message)`, `Crypto(message)` | Struct variants with a source | [Read the cause](#read-the-cause-from-source) |
| `Base64(error)`, `Deflate(error)`, or `?` on a `base64::DecodeError` or `std::io::Error` | Opaque sources, no `From` | [Convert the errors yourself](#convert-base64-and-io-errors-yourself) |
| A pattern that lists every field of a `SamlError` variant, or code that builds a variant such as `SamlError::IssuerMismatch { .. }` | Variants with fields are non-exhaustive | [End field patterns with `..`](#end-field-patterns-with-) |
| `saml_rs::error::SignatureVerificationReason` and the other reason enums | Also exported at the crate root | [Import the reason enums](#import-the-reason-enums-from-the-crate-root) |

## Read the status from `StatusNotSuccess`

`StatusNotSuccess` carries the same `Status` that `RespondSso::status` and
`RespondSlo::status` take. Before the upgrade, it held two strings:

```rust,ignore
match error {
	SamlError::StatusNotSuccess { top, second } => {
		let denied = top == status_code::RESPONDER
			&& second.as_deref() == Some(status_code::AUTH_FAILED);
	}
	_ => {}
}
```

After the upgrade, compare the typed codes:

```rust
use saml_rs::{SamlError, SubordinateStatusCode, TopLevelStatusCode};

fn authentication_failed(error: &SamlError) -> bool {
	matches!(
		error,
		SamlError::StatusNotSuccess { status, .. }
			if status.top_level() == TopLevelStatusCode::Responder
				&& status.subordinate().map(SubordinateStatusCode::as_uri)
					== Some(saml_rs::constants::status_code::AUTH_FAILED)
	)
}
```

`status.top_level().as_uri()` and
`status.subordinate().map(SubordinateStatusCode::as_uri)` return the strings
the old fields held. An empty subordinate `Value` reads as no subordinate code.

A top-level code outside the four that Core §3.2.2.2 lists, such as
`urn:example:status:Unknown`, now returns `ProtocolProfile` instead of
`StatusNotSuccess`. The response is rejected as before, after the same
signature, `Issuer`, `InResponseTo`, and `Destination` checks.

## Read the replay key from `ReplayDetected`

`ReplayDetected` carries the `ReplayKey` that was already accepted, not its
cache string. Before the upgrade:

```rust,ignore
SamlError::ReplayDetected { key } if key.starts_with("assertion_id:") => {}
```

After the upgrade, match the key family, or call `cache_key()` for the old
`kind:value` string:

```rust
use saml_rs::{ReplayKey, SamlError};

fn replayed_assertion(error: &SamlError) -> Option<&str> {
	match error {
		SamlError::ReplayDetected {
			key: ReplayKey::Assertion(id),
		} => Some(id.as_str()),
		_ => None,
	}
}
```

A second resolution of the same artifact with a replay cache returns
`ReplayKey::Artifact` with the artifact. Before the upgrade, `key` held the
bare artifact value. The cache is now the `ReplayCache` of the validation
context. See
[Resolve an artifact](soap-artifact-discovery.md#resolve-an-artifact-with-a-channel-and-a-validation-context).
`ReplayKey` is non-exhaustive, so a `match` on it needs a wildcard arm.

## Report replay cache failures with `ReplayCacheUnavailable`

A cache that cannot check or store a key returns
`ReplayCacheUnavailable` with the storage error as its source. Before the
upgrade, an implementation had only `Invalid(String)` for this:

```rust,ignore
let stored = self.store.insert(key.cache_key(), expires_at)
	.map_err(|error| SamlError::Invalid(error.to_string()))?;
```

After the upgrade:

```rust
use std::time::SystemTime;
use saml_rs::{ReplayCache, ReplayKey, SamlError};

struct SharedCache;

impl SharedCache {
	fn insert(&mut self, _key: String, _expires_at: SystemTime) -> Result<bool, std::io::Error> {
		Ok(true)
	}
}

impl ReplayCache for SharedCache {
	fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
		let inserted = self
			.insert(key.cache_key(), expires_at)
			.map_err(|error| SamlError::ReplayCacheUnavailable {
				source: Box::new(error),
			})?;
		if inserted {
			Ok(())
		} else {
			Err(SamlError::ReplayDetected { key })
		}
	}
}
```

`InMemoryReplayCache` returns `ReplayCacheUnavailable` when its entry limit
is reached, and its `Mutex` adapters return it for a poisoned lock. Treat the
variant as a server-side failure: the message itself can be genuine.

## Match the new variants instead of message text

These failures returned `Invalid`, `Xml`, or `Crypto` with a message. Match
the variant in the right column:

| Before | After |
| --- | --- |
| `Invalid` with `ERR_XML_LIMIT_EXCEEDED` | `LimitExceeded` with the `ResourceLimit::Xml*` limit and its `maximum` |
| `Invalid` with `ERR_BASE64_OUTPUT_LIMIT_EXCEEDED` | `LimitExceeded` with `ResourceLimit::Base64DecodedBytes` |
| `Invalid` with `ERR_DEFLATE_OUTPUT_LIMIT_EXCEEDED` | `LimitExceeded` with `ResourceLimit::InflatedBytes` |
| `Invalid` with `ERR_DECRYPTION_LIMIT_EXCEEDED` | `LimitExceeded` with `ResourceLimit::DecryptionWork` |
| `Invalid` for a received `RelayState` over 4096 bytes | `LimitExceeded` with `ResourceLimit::RelayStateBytes` |
| `Invalid` for a full or poisoned `InMemoryReplayCache` | `ReplayCacheUnavailable` |
| `Invalid` when the `with_recipient_endpoint` URL is not published | `RecipientEndpointNotPublished` |
| `Invalid` when several receiving endpoints are published and none is selected | `RecipientEndpointAmbiguous` |
| `Invalid` with `ERR_AMBIGUOUS_FLOW_INPUT`, `ambiguous form field`, `ambiguous Redirect field {name}`, `ambiguous SAMLart`, or `ambiguous RelayState` | `DuplicateBindingParameter { name, .. }` |
| `Invalid` with `missing form field {name}`, `missing Redirect field {name}`, or `missing SAMLart` | `MissingBindingParameter { name, .. }` |
| `Invalid` with `ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG` | `AuthnRequestSigningRequired` |
| `Xml` with `ERR_EMPTY_ASSERTION` | `AssertionMissing` |
| `Crypto` with `ERR_UNDEFINED_ENCRYPTED_ASSERTION` | `EncryptionRequired { element: "Assertion", .. }` for a plaintext assertion, `AssertionMissing` for none |
| `Crypto` for XML that signature verification or decryption could not parse | `Xml` with the parser error as `source` |

Before the upgrade, a limit check compared text:

```rust,ignore
let too_large = matches!(&error, SamlError::Invalid(message)
	if message.contains("ERR_XML_LIMIT_EXCEEDED"));
```

After the upgrade:

```rust
use saml_rs::{ResourceLimit, SamlError};

fn http_status(error: &SamlError) -> u16 {
	match error {
		SamlError::LimitExceeded {
			limit: ResourceLimit::XmlBytes | ResourceLimit::InflatedBytes,
			..
		} => 413,
		SamlError::ReplayCacheUnavailable { .. } => 503,
		_ => 400,
	}
}
```

A signed success `Response` without an assertion used to return
`IssuerMismatch { actual: None, .. }`. It now returns `AssertionMissing`.

A signed error `Response` sent to a service provider that requires encrypted
assertions used to fail with `Crypto` and
`ERR_UNDEFINED_ENCRYPTED_ASSERTION`, which hid the identity provider's status.
It now returns `StatusNotSuccess` after the same signature, `Issuer`,
`InResponseTo`, and `Destination` checks as an unencrypted one.

These messages changed text and keep their variant:

| Variant | Old message | New message |
| --- | --- | --- |
| `Invalid` | `ERR_UNSAFE_POST_BINDING_ACTION_URL` | `POST form action must be an absolute HTTP(S) URL` |
| `Invalid` | `ERR_PARTIAL_POST_BINDING_SIGNATURE` | `POST form needs both SigAlg and Signature, or neither` |
| `Invalid` | `ERR_UNDEFINED_PARSERTYPE` | `flow options name no parser type` |
| `Xml` | `ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR` | `metadata has more than one EntityDescriptor` |

The `Display` text of `InvalidInResponseTo` is now
`request ID for response correlation is empty`, and that of
`PotentialWrappingAttack` is `signature wrapping attempt detected`.

## Replace the binding and status variants

`UndefinedBinding` is removed. Each case it covered returns a variant that
names the binding or the mistake:

| Case | After |
| --- | --- |
| `SsoRequestBinding`, `SsoResponseBinding`, `LogoutBinding`, or `NameIdManagementBinding` `try_from` a binding it does not support | `UnsupportedBinding { binding, .. }` |
| An `Inbound` or raw context whose binding the operation does not handle | `UnsupportedBinding { binding, .. }` |
| `Outbound::redirect_url`, `post_form`, `soap_request`, or `soap_response` on another binding | `OutboundBindingMismatch { actual, .. }` |
| A pending snapshot whose binding name is not a SAML binding | `Invalid` |

`UndefinedStatus` is renamed `StatusMissing`. Its `Display` text is
`response status code is missing`.

```rust
use saml_rs::constants::Binding;
use saml_rs::{AuthnRequest, Outbound, SamlError};

fn redirect_location(outbound: &Outbound<AuthnRequest>) -> Result<&str, String> {
	match outbound.redirect_url() {
		Ok(url) => Ok(url),
		Err(SamlError::OutboundBindingMismatch {
			actual: Binding::Post,
			..
		}) => Err("this request is an HTTP-POST form; render post_form() instead".into()),
		Err(error) => Err(error.to_string()),
	}
}
```

## Match `BindingSignature`

`SignatureVerificationReason::DetachedMessageSignature` is renamed
`BindingSignature`. It still means that the `Signature` parameter of an
HTTP-Redirect or HTTP-POST-SimpleSign message failed verification. The new
name matches `SsoSession::binding_signature_algorithm_uri()`. XML-DSig uses
"detached" for a kind of XML signature, which this one is not. The `Display`
text is `binding signature`.

```rust
use saml_rs::{SamlError, SignatureVerificationReason};

fn binding_signature_failed(error: &SamlError) -> bool {
	matches!(
		error,
		SamlError::SignatureVerification {
			reason: SignatureVerificationReason::BindingSignature,
			..
		}
	)
}
```

## Read the cause from `source`

`Xml` and `Crypto` are struct variants. `message` says what failed. When a
parser or the XML security backend caused the failure, `source` holds that
error, and `std::error::Error::source` returns it. The cause is no longer
copied into `message` or into the `Display` text.

```rust,ignore
// Before
SamlError::Xml(message) => log::warn!("bad XML: {message}"),
```

```rust
use std::error::Error;
use saml_rs::SamlError;

fn log_line(error: &SamlError) -> String {
	let mut line = error.to_string();
	let mut cause = error.source();
	while let Some(next) = cause {
		line.push_str(": ");
		line.push_str(&next.to_string());
		cause = next.source();
	}
	line
}

fn is_xml(error: &SamlError) -> bool {
	matches!(error, SamlError::Xml { .. })
}
```

An error reporter such as `anyhow` prints the same chain with `{:#}`.

## Convert base64 and I/O errors yourself

`SamlError` no longer implements `From<base64::DecodeError>` or
`From<std::io::Error>`. `Base64` and `Deflate` are struct variants whose
`source` is an opaque `Box<dyn Error + Send + Sync>`, so neither type is part
of the public API. A function that used `?` on those errors and returned
`SamlError` no longer compiles:

```rust,ignore
fn decode(field: &str) -> Result<Vec<u8>, SamlError> {
	Ok(STANDARD.decode(field)?)
}
```

Return your own error type, or wrap the error in a `SamlError` variant on
purpose:

```rust
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

fn decode(field: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
	Ok(STANDARD.decode(field)?)
}
```

## End field patterns with `..`

Every `SamlError` variant with named fields is `#[non_exhaustive]`, except
`ReplayDetected` and `ReplayCacheUnavailable`. A later release can add a field
to such a variant without breaking you. Outside `saml-rs`, a pattern on one of
these variants ends with `..`, and code cannot build one.

Before the upgrade, a pattern could list every field:

```rust,ignore
SamlError::IssuerMismatch { expected, actual } => log_issuer(expected, actual),
```

After the upgrade:

```rust
use saml_rs::SamlError;

fn issuer(error: &SamlError) -> Option<(&str, Option<&str>)> {
	match error {
		SamlError::IssuerMismatch {
			expected, actual, ..
		} => Some((expected, actual.as_deref())),
		_ => None,
	}
}
```

A test that built one of these variants as a fake error builds its own error
type instead. A `ReplayCache` implementation still returns
`SamlError::ReplayDetected { key }` and
`SamlError::ReplayCacheUnavailable { source }` directly.

## Import the reason enums from the crate root

`SignatureVerificationReason`, `ReferenceResolutionReason`,
`SubjectConfirmationReason`, `TimeWindowField`, and the new `ResourceLimit`
are exported next to `SamlError`. The `saml_rs::error` paths still work.

```rust
use saml_rs::{ResourceLimit, SamlError, SignatureVerificationReason, TimeWindowField};
# let _ = (ResourceLimit::XmlBytes, SignatureVerificationReason::XmlSignature, TimeWindowField::Conditions);
# let _: Option<SamlError> = None;
```
