# Update truncated XML HMAC signatures

If a peer sends an enveloped XML signature with `ds:HMACOutputLength`,
HMAC-SHA384 now requires at least 192 bits and HMAC-SHA512 requires at least
256 bits. Shorter signatures fail verification.

For an affected signature on a `Response` or `Assertion`, the verifier
reports `SamlError::SignatureVerification`. Under
`XmlSignatureProfile::StrictRsaSha2`, this can replace the previous
`SamlError::AlgorithmUnsupported` result.

Configure the sending peer to emit a full-length MAC and omit
`ds:HMACOutputLength`, or configure it to truncate at or above the new
minimum. Regenerate the signature after changing the length. The receiving
application can keep its existing Rust API calls and shared-secret settings.
