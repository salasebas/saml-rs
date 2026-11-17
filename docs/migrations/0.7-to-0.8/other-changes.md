# 8. Smaller changes you may notice

[How to upgrade from 0.7 to 0.8](README.md)

These need no code change in a conformant deployment. Check them if you
compare outputs or match specific errors.

| Change | Before | Now |
| --- | --- | --- |
| `SsoSession::verified_xml_signatures` with a holder-of-key assertion before the bearer assertion | Reported the holder-of-key signature as `ConsumedAssertion` and dropped the bearer one | Reports the signature of the consumed bearer assertion. Acceptance is unchanged |
| A signed `Response` that mixes a plaintext `Assertion` and an `EncryptedAssertion` | `SamlError::Crypto` | Accepted when every assertion passes its checks. Under `RequireSigned` each plaintext assertion needs its own signature. A signature over the ciphertext is not reported as `ConsumedAssertion` evidence |
| A replayed or stale `LogoutRequest` or Redirect `ManageNameIDRequest` with an encrypted identifier | Could return the decryption error | Returns the replay, issuer, or age error before decrypting. `receive_slo` stores the request ID before decrypting |
| `ForceAuthn`, `IsPassive`, `AllowCreate`, and `AssertionConsumerServiceIndex` padded with XML whitespace in a received `AuthnRequest` | `SamlError::Invalid` | Read after trimming |
| A first `SingleSignOnService` or `SingleLogoutService` with an empty `Location` | `get_single_sign_on_service` and `get_single_logout_service` could return it | Skipped, so a later endpoint with a location is used, as the location lists already did. `get_support_bindings` omits a binding with no location |
| A Redirect or Artifact endpoint URL with a `#fragment`, or ending in `?` | Parameters went inside the fragment, or after `??` | Parameters join the query before the fragment |
| `SignatureConfig` with `Prepend` or `Append` on an empty element such as `<AuthnRequest/>` | Signature written outside the element | Signature written inside it. Refresh golden files of signed output |
| Bare certificate text with a non-ASCII character across a 64-byte boundary | Panic | `SamlError::Crypto` |
| A PAOS `AuthnRequest` without an assertion consumer URL or index | `SamlError::Invalid` | Answered at the service provider's default HTTP-POST or HTTP-POST-SimpleSign assertion consumer |
| A signature rejected by every trusted key, or two signatures that both fail a later check | The error came from the last metadata certificate | The error comes from the first rejection in key order, or the first signature in document order. The variant can differ |
| `respond_sso` or `respond_sso_artifact` for a request with no usable assertion consumer and a `Subject` with confirmations | `SamlError::Unsupported` | `SamlError::MissingMetadata("AssertionConsumerService")` |
| `Debug` of `IdpDescriptor` and `SpDescriptor` | Printed the metadata XML and parsed metadata | Prints the raw provider. Secrets stay redacted |
