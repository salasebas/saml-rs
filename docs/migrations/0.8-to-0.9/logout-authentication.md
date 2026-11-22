# Authenticate browser logout messages

Both the SP and the IdP now verify the sender's signature in `receive_slo`
and `finish_slo` for HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign.
If a peer previously sent unsigned messages, configure it to sign both
logout requests and responses before upgrading. Configure the peer descriptor
with the verification credential for that signature.
With a crypto provider, an otherwise valid unsigned POST or Redirect
message returns `SamlError::SignatureMissing`. A SimpleSign form also
requires the detached signature controls.

Remove the `logout` field assignments from `SpValidationPolicy` and
`IdpValidationPolicy` and remove imports of `LogoutPolicy` and
`LogoutSignaturePolicy`. This also applies if you explicitly selected
`RequireSigned`. Callers that used the defaults need no code changes.

```diff
-let mut validation = SpValidationPolicy::default();
-validation.logout.requests = LogoutSignaturePolicy::AllowUnsignedForCompatibility;
-validation.logout.responses = LogoutSignaturePolicy::AllowUnsignedForCompatibility;
+let validation = SpValidationPolicy::default();
```

On SOAP, pass the actual channel protection to `Inbound::soap`. The receiver
accepts an unsigned envelope's SAML message only when the deployment attests
mutual peer authentication and message integrity. It verifies any present
message signature even on that channel.

Without a crypto provider, the default IdP configuration can now be built
for protocol-only operations. Browser `receive_slo` and `finish_slo`
can no longer succeed in this configuration. Signature verification returns
`SamlError::Unsupported`. Enable a crypto provider to receive browser logout.
