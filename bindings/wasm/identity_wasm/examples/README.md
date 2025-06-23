![banner](https://github.com/iotaledger/identity/raw/HEAD/.github/banner_identity.svg)

## IOTA Identity Examples

The following code examples demonstrate how to use the IOTA Identity Wasm bindings in JavaScript/TypeScript.

The examples are written in TypeScript and can be run with Node.js.

### Prerequisites

Examples can be run against
- a local IOTA node
- or an existing network, e.g. the IOTA testnet

When setting up the local node, you'll also need to publish an identity package as described in
[Local Network Setup](https://docs.iota.org/iota-identity/getting-started/local-network-setup) in the documentation portal.
You'll also need to provide an environment variable `IOTA_IDENTITY_PKG_ID` set to the package-id of your locally deployed
identity package, to be able to run the examples against the local node.

In case of running the examples against an existing network, this network needs to have a faucet to fund your accounts (the IOTA testnet (`https://api.testnet.iota.cafe`) supports this), and you need to specify this via `NETWORK_URL`.

The examples require you to have the node you want to use in the iota clients "envs" (`iota client env`) configuration. If this node is configured as `localnet`, you don't have to provide it when running the examples, if not, provide its name as `NETWORK_NAME_FAUCET`. The table below assumes - in case you're running a local node - you have it configured as `localnet` in your IOTA clients "env" setting.

### Environment variables

Summarizing the last point, you'll need one or more of the following environment variables:

| Name                 | Required for local node | Required for testnet | Required for other node |       Comment        |
| -------------------- | :---------------------: | :------------------: | :---------------------: | :------------------: |
| IOTA_IDENTITY_PKG_ID |            x            |                      |            x            |                      |
| NETWORK_URL          |                         |          x           |            x            |                      |
| NETWORK_NAME_FAUCET  |                         |          x           |            x            | see assumption above |

### Node.js

Install the dependencies:

```bash
npm install
```

Build the bindings:

```bash
npm run build
```

Then, run an example using the following command, environment variables depend on your setup, see [Environment variables](#environment-variables).

```bash
IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555 npm run example:node -- <example-name>
```

For instance, to run the `0_create_did` example with the following (environment variables depend on you setup, see [Environment variables](#environment-variables)):

```bash
IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555 npm run example:node -- 0_create_did
```

## Basic Examples

The following basic CRUD (Create, Read, Update, Delete) examples are available:

| Name                                                | Information                                                                 |
| :-------------------------------------------------- | :-------------------------------------------------------------------------- |
| [0_create_did](src/0_basic/0_create_did.ts)         | Demonstrates how to create a DID Document and publish it in a new identity. |
| [1_update_did](src/0_basic/1_update_did.ts)         | Demonstrates how to update a DID document in an existing identity.          |
| [2_resolve_did](src/0_basic/2_resolve_did.ts)       | Demonstrates how to resolve an existing DID in an identity.                 |
| [3_deactivate_did](src/0_basic/3_deactivate_did.ts) | Demonstrates how to deactivate a DID in an identity.                        |
| [5_create_vc](src/0_basic/5_create_vc.ts)           | Demonstrates how to create and verify verifiable credentials.               |
| [6_create_vp](src/0_basic/6_create_vp.ts)           | Demonstrates how to create and verify verifiable presentations.             |
| [7_revoke_vc](src/0_basic/7_revoke_vc.ts)           | Demonstrates how to revoke a verifiable credential.                         |

## Advanced Examples

The following advanced examples are available:

| Name                                                         | Information                                                             |
| :----------------------------------------------------------- | :---------------------------------------------------------------------- |
| [4_custom_resolution](src/1_advanced/4_custom_resolution.ts) | Demonstrates how to set up a resolver using custom handlers.            |
| [5_domain_linkage](src/1_advanced/5_domain_linkage.ts)       | Demonstrates how to link a domain and a DID and verify the linkage.     |
| [6_sd_jwt](src/1_advanced/6_sd_jwt.ts)                       | Demonstrates how to create a selective disclosure verifiable credential |
| [7_status_list_2021](src/1_advanced/7_status_list_2021.ts)   | Demonstrates how to revoke a credential using `StatusList2021`.         |
| [8_zkp](./1_advanced/8_zkp.ts)                               | Demonstrates how to create an Anonymous Credential with BBS+.           |
| [9_zkp_revocation](./1_advanced/9_zkp_revocation.ts)         | Demonstrates how to revoke a credential.                                |
| [10_sd_jwt_vc](./1_advanced/10_sd_jwt_vc.rs)                 | Demonstrates how to use SD-JWT-based Verifiable Credentials.            |

<!--

## Browser

While the examples should work in a browser environment, we do not provide browser examples yet.

-->
