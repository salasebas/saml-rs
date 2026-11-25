# Common message fields

Core §3.2.1 and §3.2.2 define the fields that every SAML request and response
shares. The typed messages of every flow write and read the required fields
and a subset of the optional ones. Each flow record holds its own rules for
`ID`, `Version`, `IssueInstant`, `Destination`, `Issuer`, and `Status`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write no `Consent` attribute, so `unspecified` applies, and do not report a received one | Library policy: no profile of the flows saml-rs implements gives `Consent` a processing rule, and an application keeps its consent records outside the message. | Core §3.2.1, §3.2.2, §8.4.1 | Always |
| Write no `StatusDetail`, and do not report a received one | Library policy: no profile of the flows saml-rs implements defines its content, so a reader could not interpret it. | Core §3.2.2.1 | Always |
| Write and report a top-level `StatusCode` and at most one subordinate code. Ignore deeper codes in a received response | Library policy: every OASIS-defined status code is a top-level or second-level code. | Core §3.2.2.2 | `Status`, `SubordinateStatusCode` |
| Write caller extensions in `Extensions` on an `AuthnRequest` only | Optional | Core §3.2.1 | `StartSso::extension` |

Single Logout writes its asynchronous marker in `Extensions` itself. See
[asynchronous logout](single-logout.md#asynchronous-single-logout).
