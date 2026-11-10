# Fixture Provenance

Some committed fixtures were derived from the npm `samlify` project during the
original conformance work.

| Field | Value |
| --- | --- |
| Source project | npm `samlify` |
| Repository | https://github.com/tngan/samlify |
| Version | `2.13.1` |
| Tag | `v2.13.1` |
| Commit | `b1ff880ab40a4b4768b3afb53ef8b88c3437079b` |
| npm tarball | https://registry.npmjs.org/samlify/-/samlify-2.13.1.tgz |
| npm integrity | `sha512-vdYr/zohDGBbfWNU4miEzc1jmWOtkLySPViapC6nfGkv9KxzLq4UlGkKyryzwLw4jVlZk88Rw93HaCRVpe+t+g==` |

These files are historical regression and provenance inputs. They are not an
active compatibility promise. New protocol behaviour is justified in
[standards conformance](../../docs/standards-conformance.md).

Fixture key material is test-only. It is not for use outside tests.

## Crypto provider matrix fixture audit

`tests/provider_regression.rs` deliberately uses the matching
`key/idp/provider_matrix_privkey.pkcs8.pem` and `key/idp/cert.cer` pair for
every provider. The private key is the unencrypted PKCS#8 encoding of the
samlify test-only IdP RSA key for `key/idp/cert.cer` (upstream
`test/key/idp/nocrypt.pem`); their public keys match.
The pair has a 2048-bit RSA key with exponent
65537 and a SHA-256-signed certificate. This avoids making provider
compatibility depend on encrypted or provider-specific private-key formats and
unusual key sizes retained for loader regressions.

The committed RSA certificate fixtures were audited for the provider matrix:
their public keys range from 2048 to 4096 bits. Historical encrypted keys and
expired certificates remain test-only inputs for their existing focused
regressions and are not provider-support or production-security claims.

## DSA signing fixture

`key/dsa/privkey.pkcs8.pem` and `key/dsa/cert.pem` are a test-only DSA key and
self-signed certificate for the DSAwithSHA1 test in
`tests/conformance_algorithms.rs`. They were generated with OpenSSL `4.1.0`:
`genpkey -genparam -algorithm DSA -pkeyopt pbits:2048 -pkeyopt qbits:256`,
`genpkey -paramfile`, and `req -new -x509 -sha256 -days 36500`.

| Artifact | SHA-256 |
| --- | --- |
| `key/dsa/privkey.pkcs8.pem` | `f068be2b52fe4950a193ec4c1ce6482cc94c1b0a64d4650a05b701d348b189cd` |
| `key/dsa/cert.pem` | `05057e2fe258d70aebff0b3540a408cbc58967fae46db4aa51fabeb48ac94d5e` |

The certificate SHA-256 fingerprint is
`2E:82:88:A6:72:6E:56:11:FA:97:56:58:AD:70:78:91:89:44:20:9B:E6:63:4C:9C:03:BD:20:2E:9D:57:02:2C`.

## External SLO HTTP-Redirect fixtures

The fixtures under `tests/fixtures/interop/` are immutable interoperability
and regression inputs. They are not a conformance certification, an OASIS
requirement to test these products, or a release gate. Tests consume the
committed query strings verbatim and never regenerate them with `saml-rs`.

All private keys and certificates in this fixture group are intentionally
public, test-only material. They are not trust anchors and they are not for
use outside tests.
The metadata files are minimal documents assembled from the generation
configuration and the corresponding public test certificate; they are not
claims about a production deployment.

### Shibboleth IdP 5.2.3 → saml-rs SP

| Field | Value |
| --- | --- |
| Producer and role | Shibboleth Identity Provider, IdP-initiated `LogoutRequest` |
| Product version | Shibboleth Identity Provider `5.2.3` |
| Distribution | Maven release artifact `net.shibboleth.idp:idp-distribution:5.2.3:zip` |
| Distribution SHA-256 | `5ad3f26cfbb76c94137b79c0ccc35c068b19e209c5f8e32b9787bafb73446e96` |
| Release source | `https://codeberg.org/Shibboleth/java-identity-provider`, tag `5.2.3`, commit `bbd2a2e17b39bbb950b9f67eb09bee48b4860452` |
| Integration harness | `https://codeberg.org/Shibboleth/java-idp-integration-tests`, commit `948a900d78e58b41fbeedf6b2557e3ce17229d69` |
| IdP testbed | Snapshot `5.2.3-20260617.132935-11`; WAR SHA-256 `7793a24d2ab04638ac0b305bc937144b7389a4e22724749fdf0ea7ff0f7857a5`; classes JAR SHA-256 `bb76db0ac097c36d2a03b7742c9691f65648db67c86159fe0b61e022bf48ffd3` |
| Runtime | Eclipse Temurin `17.0.19+10`, Maven `3.9.16`, Jetty `12.1.10`, Chrome `150.0.7871.129`, Selenium `4.44.0` |
| Binding and encoder | Full IdP product flow over HTTP-Redirect, captured from Chrome's network log |
| Direction under test | `Saml<Sp>::receive_slo` |
| Entity ID | `https://idp.example.org` |
| Destination | `https://localhost:24720/sp/SAML2/Redirect/SLO` |
| Signature | RSA-SHA256 detached Redirect signature |
| Subject identifier | Default `<EncryptedID>` emitted by the configured IdP |
| RelayState | Absent |
| License/source note | Shibboleth IdP is distributed under Apache License 2.0; only emitted test data and locally generated test credentials are committed |

The official integration harness installed the release IdP, started it in
Jetty, completed SSO and consent against the official testbed SP, enabled
tracked SP sessions, and then followed the IdP's global-logout propagation
flow. Chrome captured the request that the running IdP sent to the testbed
SP's Redirect SLO endpoint. The part after `?` is committed unchanged as
`logout-request.query`.

The IdP installer generated the committed RSA-3072 test signing key and
certificate for that run. `idp-metadata.xml` is a minimal receiver-side
descriptor assembled from the captured certificate, query issuer, and
runtime endpoints; it is not a verbatim product metadata export. The exact
harness patch, Maven settings, commands, and extraction command are recorded
in [the reproduction recipe](interop/REPRODUCING.md#shibboleth-idp-523).

Shibboleth emitted `<EncryptedID>` in this default front-channel flow.
`saml-rs` authenticates and parses the request and exposes its SessionIndex.
It decrypts the identifier only with a decryption key. The encrypted key
targets the testbed entity `https://sp.example.org`, not the receiver
configured in this regression test, which has no decryption key, so the
identifier stays unread. The fixture therefore proves authenticated parsing
only: it does not prove subject correlation, session invalidation, or complete
Session Participant processing under SAML Core section 3.7.3.1. Decrypting
this vector needs the testbed SP key, which is not committed, so it does not
claim typed subject-processing interoperability.

| Artifact | SHA-256 |
| --- | --- |
| `shibboleth-idp-5.2.3/logout-request.query` | `b8e4d96aaa902c180d491f314fe4e47f6b2bfa18cd2900f243b9fa651770fffb` |
| `shibboleth-idp-5.2.3/idp-metadata.xml` | `78a6c50559969f88ee82d141ceb01a1fc8cedb7314033647be82a8d33e29898f` |
| `shibboleth-idp-5.2.3/idp-signing-cert.pem` | `a9103584081e85f02d146c7ccae7ce219cd88a167ed0df798c8b37f4ad00f435` |
| `shibboleth-idp-5.2.3/idp-signing-key.pem` | `fd97cd3c7bb5386048d74cce24fe77a626f76c9bbcbc53025407f752f43c3d18` |

The certificate SHA-256 fingerprint is
`8A:4B:D0:22:0E:54:DE:F3:38:C5:60:07:7C:BE:1B:93:E5:B9:18:0A:25:49:A4:8D:25:DC:E4:7E:2F:E0:09:92`.

### SimpleSAMLphp 2.5.2 SP → saml-rs IdP

| Field | Value |
| --- | --- |
| Producer and role | SimpleSAMLphp configured as a Service Provider, SP-initiated `LogoutRequest` |
| Product version | SimpleSAMLphp `2.5.2`, release commit `e04c29a` |
| Distribution | https://github.com/simplesamlphp/simplesamlphp/releases/download/v2.5.2/simplesamlphp-2.5.2-full.tar.gz |
| Distribution SHA-256 | `1394883cc15fb532b9cbac899377caac72163aaab964c0c67a793a69142a8902` (published on the `v2.5.2` release page) |
| SLO implementation dependency | `simplesamlphp/saml2-legacy` `v4.20.3`, commit `b43d5d10ea1180f478ddcd677ff13bb324cfa866` from the release's `composer.lock` |
| Runtime | PHP `8.3.32`, container image digest `sha256:2a3f699b6cb31e5638c5432e4d37d4047853ba6351a692c91e0a073af00a55cc` |
| Binding and encoder | HTTP-Redirect via `SAML2\HTTPRedirect::getRedirectURL` |
| Direction under test | `Saml<Idp>::receive_slo` |
| Entity ID | `https://sp.example.test/saml2` |
| Destination | `https://idp.example.test/slo/redirect` |
| Signature | RSA-SHA256 detached Redirect signature |
| RelayState | `simplesamlphp-sp-state` |
| License/source note | SimpleSAMLphp and `saml2-legacy` are LGPL-2.1-or-later; only emitted test data and locally generated test credentials are committed |

The full release archive was run without modifying its source or vendor tree.
The SimpleSAMLphp global configuration set `certdir=/fixtures`. The hosted SP
metadata set `entityid`, `privatekey`, `certificate`, `sign.logout=true`, and
`signature.algorithm` to RSA-SHA256. The remote IdP metadata set its entity ID
and `sign.logout=true`. Production helper
`SimpleSAML\Module\saml\Message::buildLogoutRequest` created and signed the
request; the test ID, timestamp, destination, RelayState, persistent NameID,
and two SessionIndex values were then set before production
`SAML2\HTTPRedirect::getRedirectURL` emitted the URL. The part after `?` is
committed unchanged as `logout-request.query`.

The generation-only PHP script, downloaded release archive, and PHP container
are not repository inputs. Its complete source, SHA-256, and exact container
command are preserved in
[the reproduction recipe](interop/REPRODUCING.md#simplesamlphp-252).

| Artifact | SHA-256 |
| --- | --- |
| `simplesamlphp-2.5.2/logout-request.query` | `e2aba02abd802a6b14f392ca05d52693223324956fa5cd680a48193d1ffc3688` |
| `simplesamlphp-2.5.2/sp-metadata.xml` | `6a328f1fb906df715b13c408e8b79300a5f0971cc4c1832edaa497f907567719` |
| `simplesamlphp-2.5.2/sp-signing-cert.pem` | `5d716dea2429aacbe29b750f5680e8276d7d71e7a4b1498c96aab46dd8245408` |
| `simplesamlphp-2.5.2/sp-signing-key.pem` | `37b34025f8f0550c2013944db90d91c87a06f4b6f79e265dd528a30215ace306` |

The RSA-2048 key and self-signed certificate were generated with OpenSSL
`3.6.2` using `genpkey` and `req -new -x509 -sha256 -days 3650`. The
certificate SHA-256 fingerprint is
`51:69:56:63:DC:8D:51:FA:6A:42:37:F2:4B:D2:08:15:24:A7:1A:70:91:84:FF:12:7F:02:9F:DF:78:7A:8F:6D`.

## Fixture Groups

Every committed fixture belongs to one of these groups. Each fixture has one
canonical path; tests and unit tests load it from that path.

- `tests/fixtures/misc/**` - historical samlify XML request, response, and
  metadata cases.
- `tests/fixtures/key/idp/**` and `tests/fixtures/key/sp/**` - historical
  samlify IdP and SP test certificates and keys. `key/idp/README.md` maps each
  IdP private key to its certificate.
- `tests/fixtures/key/dsa/**` - the DSA signing fixture described above.
- `tests/fixtures/interop/**` - immutable external interoperability inputs and
  associated public test-only keys and metadata. The signing keys and
  certificates are not loaded by tests; they are kept with their SHA-256
  values. The SimpleSAMLphp recipe in `interop/REPRODUCING.md` reads its
  committed key; the Shibboleth key and certificate are the ones its installer
  generated for the capture, and a new run generates a fresh pair.

The SP signing pair is `key/sp/privkey.unencrypted.pkcs8.pem` with
`key/sp/cert.unencrypted.pkcs8.cer`. `key/sp/privkey.encrypted.pkcs8.pem` is
a different, passphrase-protected key that tests load only to exercise
encrypted private-key loading.

Byte-identical copies of `misc/` documents at the top of `tests/fixtures/`,
and the flat `key/idp_cert.cer`, `key/sp_cert.cer`, `key/sp_signing_cert.cer`,
`key/sp_privkey.pem`, and `key/sp_privkey_enc.pem` copies of `key/idp/` and
`key/sp/` files, were removed in favour of the canonical paths above. Samlify
fixtures that no test loaded were removed as well. These kept files have
their partner only upstream, in samlify at the pinned commit:

| Kept file | Partner upstream |
| --- | --- |
| `key/sp/privkey.encrypted.pkcs8.pem` | `test/key/sp/cert.encrypted.pkcs8.cer` |
| `key/sp/encryptKey.pem` | `test/key/sp/encryptionCert.cer` (also embedded in `misc/spmeta.xml`) |
| `key/sp/cert.cer` | `test/key/sp/privkey.pem` |
| `key/idp/encryptionCert.cer` | `test/key/idp/encryptKey.pem` |
