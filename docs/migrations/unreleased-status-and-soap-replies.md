# Handle status shape errors and SOAP replies

## Expect an error for a response with more than one status

The protocol schema gives a SAML response exactly one `Status`. That
`Status` holds exactly one top-level `StatusCode`. A `StatusCode` holds at
most one subordinate `StatusCode`, and every `StatusCode` carries `Value`.
The protocol schema also allows at most one `Issuer` on a response.

saml-rs now enforces that shape when it reads the status of a received
`Response`, `LogoutResponse`, `ManageNameIDResponse`, or `ArtifactResponse`.
Before, saml-rs read the first matching `StatusCode` and ignored the others. `ArtifactResolution::finish` read the first `Issuer`.

A response that breaks the shape now returns `SamlError::ProtocolProfile`
from `ServiceProvider::finish_sso`, `accept_unsolicited_sso`, `finish_slo`
on both roles, `finish_name_id_management_redirect` on both roles,
`StartedNameIdManagement::finish`, and `ArtifactResolution::finish`. A
missing `Status`, `StatusCode`, or top-level `Value` still returns
`SamlError::StatusMissing`.

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
