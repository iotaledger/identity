![banner](https://github.com/iotaledger/identity/raw/HEAD/.github/banner_identity.svg)

## IOTA Identity Examples

The following code examples demonstrate how to use IOTA Identity.

### Prerequisites

Examples can be run against
- a local IOTA node
- or an existing network, e.g. the IOTA testnet

When setting up the local node, you'll also need to publish an identity package as described in
[Local Network Setup](https://docs.iota.org/iota-identity/getting-started/local-network-setup) in the documentation portal.
You'll also need to provide an environment variable `IOTA_IDENTITY_PKG_ID` set to the package-id of your locally deployed
identity package, to be able to run the examples against the local node.
If running the examples on `testnet`, use the `IOTA_IDENTITY_PKG_ID` `0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555`.

In case of running the examples against an existing network, this network needs to have a faucet to fund your accounts (the IOTA testnet (`https://api.testnet.iota.cafe`) supports this), and you need to specify this via `API_ENDPOINT`.

The examples require you to have the node you want to use in the iota clients "envs" (`iota client env`) configuration, as the client is used to request funds from the configured network's faucet.

### Environment variables

Summarizing the last point, you'll need one or more of the following environment variables:

| Name                 | Required for local node | Required for testnet | Required for other node |
| -------------------- | :---------------------: | :------------------: | :---------------------: |
| IOTA_IDENTITY_PKG_ID |            x            |          x           |            x            |
| API_ENDPOINT         |                         |          x           |            x            |

### Running examples

Run an example using the following command, environment variables depend on your setup, see [Environment variables](#environment-variables).

```bash
IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555 cargo run --example <example-name>
```

For instance, to run the `0_create_did` example with the following (environment variables depend on you setup, see [Environment variables](#environment-variables)):

```bash
IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555 cargo run --release --example 0_create_did
```

## Basic Examples

The following basic CRUD (Create, Read, Update, Delete) examples are available:

| Name                                                    | Information                                                                 |
| :------------------------------------------------------ | :-------------------------------------------------------------------------- |
| [0_create_did](./0_basic/0_create_did.rs)               | Demonstrates how to create a DID Document and publish it in a new identity. |
| [1_update_did](./0_basic/1_update_did.rs)               | Demonstrates how to update a DID document in an existing identity.          |
| [2_resolve_did](./0_basic/2_resolve_did.rs)             | Demonstrates how to resolve an existing DID in an identity.                 |
| [3_deactivate_did](./0_basic/3_deactivate_did.rs)       | Demonstrates how to deactivate a DID in an identity.                        |
| [5_create_vc](./0_basic/5_create_vc.rs)                 | Demonstrates how to create and verify verifiable credentials.               |
| [6_create_vp](./0_basic/6_create_vp.rs)                 | Demonstrates how to create and verify verifiable presentations.             |
| [7_revoke_vc](./0_basic/7_revoke_vc.rs)                 | Demonstrates how to revoke a verifiable credential.                         |
| [8_legacy_stronghold](./0_basic/8_legacy_stronghold.rs) | Demonstrates how to use stronghold for secure storage.                      |                     |

## Advanced Examples

The following advanced examples are available:

| Name                                                                                   | Information                                                                                          |
| :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------|
| [4_identity_history](./1_advanced/4_identity_history.rs)                               | Demonstrates fetching the history of an identity.                                                    |
| [5_custom_resolution](./1_advanced/5_custom_resolution.rs)                             | Demonstrates how to set up a resolver using custom handlers.                                         |
| [6_domain_linkage](./1_advanced/6_domain_linkage)                                      | Demonstrates how to link a domain and a DID and verify the linkage.                                  |
| [7_sd_jwt](./1_advanced/7_sd_jwt)                                                      | Demonstrates how to create and verify selective disclosure verifiable credentials.                   |
| [8_status_list_2021](./1_advanced/8_status_list_2021.rs)                               | Demonstrates how to revoke a credential using `StatusList2021`.                                      |
| [9_zkp](./1_advanced/9_zkp.rs)                                                         | Demonstrates how to create an Anonymous Credential with BBS+.                                        |
| [10_zkp_revocation](./1_advanced/10_zkp_revocation.rs)                                 | Demonstrates how to revoke a credential.                                                             |
| [11_linked_verifiable_presentation](./1_advanced/11_linked_verifiable_presentation.rs) | Demonstrates how to link a public Verifiable Presentation to an identity and how it can be verified. |