# Match artifact refusal reasons

[How to upgrade from 0.8 to 0.9](README.md)

If you match on `ArtifactRelease::Withheld` after `answer_artifact_resolve`,
rename the `ArtifactWithheld` variants in your match arms.

| Before | After | When the identity provider withholds the message |
| --- | --- | --- |
| `ArtifactWithheld::Channel` | `ArtifactWithheld::InsufficientChannelProtection` | The SOAP channel lacks the protection required for the stored message. |
| `ArtifactWithheld::Destination` | `ArtifactWithheld::DestinationMismatch` | The request's `Destination` differs from the artifact resolution endpoint. |
