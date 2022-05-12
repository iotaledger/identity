---
title: CredentialInfo
sidebar_label: CredentialInfo
---

:::info

The IOTA DIDComm Specification is in the RFC phase and may undergo changes. Suggestions are welcome at [GitHub #464](https://github.com/iotaledger/identity.rs/discussions/464).

:::

- Status: `IN-PROGRESS`
- Last Updated: 2021-10-29

`CredentialInfo` objects allow parties to negotiate which kinds of [verifiable credentials][VC] they want to issue or exchange. [Verifiable credential][VC] kinds can be described by different attributes such as the [`type`](https://www.w3.org/TR/vc-data-model/#types) and [`@context`](https://www.w3.org/TR/vc-data-model/#contexts) fields or the structure of the data in the payload. `CredentialInfo` provides methods to specify the identifying characteristics of a credential.

Currently, only `CredentialType2021` is prescribed but additional `CredentialInfo` methods may be introduced in the future, e.g. to account for selective disclosure of particular fields. If full schema negotiation of credentials is required, refer to the external [Presentation Exchange 1.0 specification](https://identity.foundation/presentation-exchange/spec/v1.0.0/).

### CredentialType2021

- Type: `CredentialType2021`

Negotiates [verifiable credentials][VC] using their [`type`][TYPE] and optional [JSON-LD][JSON-LD] [`@context`][CONTEXT]. The [`issuer`][ISSUER] field may also be included depending on the protocol and usage.

```json
{
  "credentialInfoType": string,  // REQUIRED
  "@context": [string],          // OPTIONAL
  "type": [string],              // REQUIRED
  "issuer": [string],            // OPTIONAL
}
```

| Field | Description | Required |
| :--- | :--- | :--- |
| `credentialInfoType` | String indicating the `CredentialInfo` method, MUST be `"CredentialType2021"`. | ✔ | 
| [`@context`][CONTEXT] | Array of [JSON-LD] [contexts][CONTEXT] referenced in the credential. | ✖ |
| [`type`][TYPE] | Array of credential [types][TYPE] specifying the kind of credential offered.[^1] | ✔ | 
| [`issuer`][ISSUER] | Array of credential [issuer][ISSUER] [DIDs](https://www.w3.org/TR/did-core/#dfn-decentralized-identifiers) or [URIs](https://www.w3.org/TR/vc-data-model/#dfn-uri).[^2] | ✖ |

[^1] The [`type`][TYPE] MAY be under-specified depending on the protocol but SHOULD always include the most general types. For example, a credential with the types `["VerifiableCredential", "DriversLicence", "EUDriversLicence", "GermanDriversLicence"]` could be specified as `["VerifiableCredential", "DriversLicence"]`. 

[^2] The [`issuer`][ISSUER] field MAY either be the single issuer of an existing credential, one or more issuers that a [verifier](../protocols/presentation#roles) would trust during a [presentation](../protocols/presentation), or one or more trusted issuers that a [holder](../protocols/issuance#roles) requests to sign their credential during an [issuance](../protocols/issuance). The [`issuer`][ISSUER] field is OPTIONAL as the [holder](../protocols/presentation#roles) may not want to reveal too much information up-front about the exact credentials they possess during a [presentation](../protocols/presentation); they may want a non-repudiable signed request from the verifier first. 

#### Examples

1. Indicate a "UniversityDegreeCredential" from a specific issuer:

```json
{
  "credentialInfoType": "CredentialType2021", 
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": ["did:example:76e12ec712ebc6f1c221ebfeb1f"]
}
```

## Unresolved Questions

- Should we implement https://w3c-ccg.github.io/vp-request-spec/ as a `CredentialInfo`?
- Should we implement https://identity.foundation/presentation-exchange/spec/v1.0.0/ as a `CredentialInfo`?

[VC]: https://www.w3.org/TR/vc-data-model
[JSON-LD]: https://json-ld.org/
[CONTEXT]: https://www.w3.org/TR/vc-data-model/#contexts
[TYPE]: https://www.w3.org/TR/vc-data-model/#types
[ISSUER]: https://www.w3.org/TR/vc-data-model/#issuer
