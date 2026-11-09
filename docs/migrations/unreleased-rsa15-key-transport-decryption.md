# RSA-v1.5 key-transport decryption

This change is unreleased. It applies to the release that first publishes
`XmlEncryptionPolicy::with_rsa15_key_transport_decryption_allowed`.

## Select RSA-v1.5 decryption for a peer that sends it

Who must change: an entity whose peer encrypts the key of an
`EncryptedAssertion`, `EncryptedAttribute`, `EncryptedID`, or `NewEncryptedID`
with RSA-v1.5 key transport (`http://www.w3.org/2001/04/xmlenc#rsa-1_5`). That
includes the `EncryptedID` of a `LogoutRequest` or `ManageNameIDRequest`.

An entity used to decrypt that key whenever RSA key-transport decryption ran.
It now rejects the message with `SamlError::Unsupported` before it decrypts
any key. RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext attack.
Messages that use RSA-OAEP are accepted as before.

Ask the peer to send RSA-OAEP. If it cannot, select RSA-v1.5 decryption on
the receiving entity's `XmlEncryptionPolicy`:

```rust
use saml_rs::{XmlEncryptionPolicy, XmlPolicy};

let xml = XmlPolicy {
    encryption: XmlEncryptionPolicy::encrypt_assertions()
        .with_insecure_software_rsa_key_transport_decryption_allowed()
        .with_rsa15_key_transport_decryption_allowed(),
    ..XmlPolicy::default()
};
```

RSA-v1.5 decryption still needs the `crypto-legacy-algorithms` feature, and
on RustCrypto the software RSA opt-in shown above.

The raw API takes the same choice as the `allow_rsa15_key_transport_decryption`
field of `AssertionDecryptionOptions` for `decrypt_assertion`, of
`EntitySetting` for the raw `ServiceProvider` and `IdentityProvider`, and of
`FlowOptions`.
