# Handle status shape errors and SOAP replies

## Expect an error for a response with more than one status

The protocol schema gives a SAML response exactly one `Status`. That
`Status` holds exactly one top-level `StatusCode`. A `StatusCode` holds at
most one subordinate `StatusCode`, and each `StatusCode` carries `Value`.
The protocol schema also allows at most one `Issuer` on a response.

saml-rs now enforces that shape for the top-level and subordinate
`StatusCode` when it reads the status of a received `Response`,
`LogoutResponse`, `ManageNameIDResponse`, or `ArtifactResponse`. It does not
read deeper codes. Before, saml-rs read the first matching `StatusCode` and
ignored the others.

A response with a second `Status`, a second top-level `StatusCode`, a second
subordinate `StatusCode`, or a subordinate `StatusCode` without `Value` now
returns `SamlError::ProtocolProfile` from `ServiceProvider::finish_sso`,
`accept_unsolicited_sso`, `finish_slo` on both roles,
`finish_name_id_management_redirect` on both roles,
`StartedNameIdManagement::finish`, and `ArtifactResolution::finish`. The
name identifier management flows already rejected a second `Status` or
top-level `StatusCode`.

A missing `Status`, top-level `StatusCode`, or top-level `Value` returns
`SamlError::StatusMissing`. Before, `StartedNameIdManagement::finish`
returned `SamlError::ProtocolProfile` for a missing `Status` or top-level
`StatusCode`.

A second `Issuer` now returns `SamlError::ProtocolProfile` from
`ArtifactResolution::finish` and `StartedNameIdManagement::finish`. Before,
both read the first `Issuer`. The other flows already rejected it.

`LogoutResponse::status` now returns the status codes that `finish_slo`
validated.

You do not need to change code. If a peer sends its subordinate code next to
the top-level code instead of inside it, ask the peer to nest it:

```xml
<samlp:Status>
	<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/>
	</samlp:StatusCode>
</samlp:Status>
```

## Attest an authenticated channel for every artifact answer

Profiles §5.3.2 and §5.4.2 require the artifact issuer to authenticate itself
and protect the integrity of every `ArtifactResponse`, including one without
the message. saml-rs does not sign `ArtifactResponse`, so the SOAP channel
must provide that protection.

`IdentityProvider::answer_artifact_resolve` now returns
`SamlError::SoapChannelProtection` before it reads the request when `channel`
does not attest `PartyAuthentication::Mutual` and
`MessageIntegrity::Protected`. Before, it answered an unknown artifact, a
different presenter, or a newer request version over any channel.
`ArtifactWithheld::InsufficientChannelProtection` now means only that the
channel is not confidential and the stored message requires confidentiality.

If your handler passes `SoapChannel::unattested()` or another weaker value,
pass the protection your TLS and HTTP layer establishes. Answer
`SoapChannelProtection` as a refused exchange, for example with HTTP 403.

```rust
let answer = idp.answer_artifact_resolve(
	&sp,
	envelope,
	&received_at,
	&mut issued,
	SoapChannel::mutually_authenticated_confidential(),
)?;
```

## Answer SOAP processing failures with a SOAP fault

Bindings §3.2.3.3 and SOAP 1.1 §6.2 require a SOAP responder to answer a SOAP
processing failure with HTTP 500 and a SOAP fault. Bindings §3.2.3.3 also
recommends HTTP 403 for a refused exchange, and E19 recommends a SAML status
with HTTP 200 for a SAML processing error.

A received envelope that saml-rs cannot process now returns
`SamlError::SoapEnvelope`. Its `fault` field is a `SoapFaultCode`:

- `VersionMismatch` for an `Envelope` outside the SOAP 1.1 namespace.
- `MustUnderstand` for a header entry addressed to the receiver with
  `mustUnderstand` set.
- `Client` for every other failure, such as malformed XML, an XML limit, or
  an envelope without exactly one `Body` element.

Before, the same failures returned `SamlError::Xml`,
`SamlError::ProtocolProfile`, or `SamlError::LimitExceeded`. The original
error is now the `source` of `SoapEnvelope`. The change applies to
`SoapBodyElement::from_envelope`, `IdentityProvider::answer_artifact_resolve`,
`IdentityProvider::receive_name_id_management`, `receive_slo` and
`finish_slo` with `Inbound::soap` on both roles, `ArtifactResolution::finish`,
and `StartedNameIdManagement::finish`.

If your SOAP handler matched those variants, match `SoapEnvelope` instead and
send `SoapFault::new` with HTTP 500:

```rust
match idp.answer_artifact_resolve(&sp, envelope, &received_at, &mut issued, channel) {
	Ok(answer) => reply(200, answer.response().envelope()),
	Err(SamlError::SoapChannelProtection) => reply(403, ""),
	Err(SamlError::SoapEnvelope { fault, .. }) => reply(500, SoapFault::new(fault).envelope()),
	Err(SamlError::ProtocolProfile(_) | SamlError::SignatureVerification { .. }) => {
		reply(500, SoapFault::new(SoapFaultCode::Client).envelope())
	}
	Err(_) => reply(500, SoapFault::new(SoapFaultCode::Server).envelope()),
}
```

To read the limit that stopped an envelope, downcast the source:

```rust
if let SamlError::SoapEnvelope { source, .. } = &error {
	if let Some(SamlError::LimitExceeded { limit, .. }) = source.downcast_ref::<SamlError>() {
		log_limit(*limit);
	}
}
```
