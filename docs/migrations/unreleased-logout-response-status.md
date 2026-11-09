# A LogoutResponse status is reported after authentication

This break is unreleased. It applies to `finish_slo` on both roles and to the
raw `parse_logout_response` and `parse_logout_response_without_request_id`.

A `LogoutResponse` with a status other than `Success` now returns
`SamlError::StatusNotSuccess` only after its signature, `Issuer`,
`InResponseTo`, and `Destination` checks pass. Before, the status came first.
A response that fails one of those checks now returns that check's error:

| Response | Before | Now |
| --- | --- | --- |
| Unsigned when signatures are required | `StatusNotSuccess` | `SignatureMissing` |
| Wrong `InResponseTo` | `StatusNotSuccess` | `InResponseToMismatch` |
| Wrong `Issuer` | `StatusNotSuccess` | `IssuerMismatch` |
| Wrong `Destination` (`finish_slo` only) | `StatusNotSuccess` | `DestinationMismatch` |

Who must change: callers that match `StatusNotSuccess` to treat a refused
logout. Handle the authentication and correlation errors as a failed logout
too. `StatusNotSuccess` now means the peer authenticated the refusal.
Under `LogoutSignaturePolicy::AllowUnsignedForCompatibility` an unsigned
response still reports its status after the correlation checks.
