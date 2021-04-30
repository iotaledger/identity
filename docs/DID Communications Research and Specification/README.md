![banner](./../../.meta/identity_banner.png)

# DID Communications Message Specification

*version 0.3, last changed April 2021*

## Resources

| Name | Description |
| :--- | :--- |
| [Field Definitions](Field_Definitions.md) | Definitions for fields used within interactions. |
| [Standalone Messages](Standalone_Messages.md) | Definitions for messages that are defined outside of a specific interaction context. |

## Interactions

| Name | Version | Messages | Description |
| :--- | :---: | :--- | :--- |
| [trust-ping](i_trust-ping.md) | 1.0 | *ping* | Testing a pairwise channel. |
| [did-discovery](i_did-discovery.md) | 1.0 | *didRequest*, *didResponse* | Requesting a DID from an agent. |
| [did-introduction](i_did-introduction.md) | 1.0 | *introductionProposal*, *introductionResponse*, *introduction* | Describes how a go-between can introduce parties that it already knows, but that do not know each other. |
| [features-discovery](i_features-discovery.md) | 1.0 | *featuresRequest*, *featuresResponse* | Enabling agents to discover which interactions other agents support. |
| [did-resolution](i_did-resolution.md) | 1.0 | *resolutionRequest*, *resolutionResponse* | Using another agent as a Resolver. |
| [authentication](i_authentication.md) | 1.0 | *authenticationRequest*, *authenticationResponse* | Proving control over a DID. |
| [credential-options](i_credential-options.md) | 1.0 | *credentialOptionsRequest*, *credentialOptionsResponse* | Querying an agent for the VCs that the agent can issue. |
| [credential-schema](i_credential-schema.md) | 1.0 | *credentialSchemaRequest*, *credentialSchemaResponse* | Querying an agent for the schema of a specific VC that the agent can issue. |
| [credential-issuance](i_credential-issuance.md) | 1.0 | *credentialSelection*, *credentialIssuance* | Creating an authenticated statement about a DID. |
| [credential-revocation](i_credential-revocation.md) | 1.0 | *revocation* | Notifying a holder that a previously issued credential has been revoked. |
| [presentation-verification](i_presentation-verification.md) | 1.0 | *presentationRequest*, *presentationResponse* | Proving a set of statements about an identifier. |

## Future Work

◈ DID Comms - Interaction - DID Authorization (AuthZ): We can do authorization through Verifiable Credentials, but this requires a standardisation of FROST (or any other policy language) and an implementation of that beforehand. The idea is to then include that in a VC `policy` field (or similar).

◈ DID Comms - Interaction - DID Introduction: If applicable, discuss opening up the protocol to n introducees, where n > 2.

◈ Standardize communication about supported signature suites in e.g. interactions about VCs.

◈ If neccessary, discuss ways for some agent to request the start of an interaction. This has narrow use cases, but might be interesting in the long run.