---
title: IOTA DID Method Specification
sidebar_label: DID Method
description: How IOTA Identity implements the Decentralized Identifiers Standard on the IOTA Tangle.
image: /img/Identity_icon.png
keywords:
- DID
- specs
- specifications
- Decentralized Identifiers
- Tangle
- format
---

# IOTA DID Method Specification

Version 0.3-draft by Jelle Millenaar, IOTA Foundation

## Abstract

The IOTA DID Method Specification describes a method of implementing the [Decentralized Identifiers](https://www.w3.org/TR/did-core/) (DID) standard on the [IOTA Tangle](https://iota.org), a Distributed Ledger Technology (DLT). It conforms to the [DID specifications v1.0 Working Draft 20200731](https://www.w3.org/TR/2020/WD-did-core-20200731/) and describes how to publish DID Document Create, Read, Update and Delete (CRUD) operations to the IOTA Tangle. In addition, it lists additional non-standardized features that are built for the IOTA Identity implementation. 

## Introduction

### The IOTA Tangle

This specification defines a method of implementing DID on top of the [IOTA Tangle](https://iota.org), which is a Distributed Ledger Technology (DLT) using a Tangle data structure. In contrast to a Blockchain, the Tangle does not store messages in blocks and chain them together, but rather creates a data structure where a message references between one and eight previous messages (used to be two, as the gif shows), creating a parallel structure. 

Blockchain | Tangle
:---------:|:---------:

![Blockchain bottleneck](/img/blockchain-bottleneck.gif) | ![Tangle Bottleneck](/img/tangle-bottleneck.gif)

For this method, the most important features of IOTA are: 

* The lack of fees, requiring no cryptocurrency tokens to be owned in order to submit a message to the DLT.
* The DLT has a public and permissionless network which runs the IOTA cryptocurrency.
* Pure data messages are possible to be stored immutably. 
* Few nodes store the entire Tangle, requiring additional logic to prove the immutability of data. 

## DID Method Name

The namestring to identify this DID method is: `iota`.

A DID that uses this method MUST begin with the following prefix: `did:iota`. Following the generic DID specification, this string MUST be lowercase.

## DID Format

The DIDs that follow this method have the following format:
```
iota-did = "did:iota:" iota-specific-idstring
iota-specific-idstring = [ iota-network ":" ] iota-tag
iota-network = char{,6}
iota-tag = base-char{44}
char = 0-9 a-z
base-char = 1-9 A-H J-N P-Z a-k m-z
```

### IOTA-Network

The iota-network is an identifier of the network where the DID is stored. This network must be an IOTA Tangle, but can either be a public or private network, permissionless or permissioned.

The following values are reserved and cannot reference other networks:
1. `main` references the main network which refers to the Tangle known to host the IOTA cryptocurrency.
2. `dev` references the development network known as "devnet" maintained by the IOTA Foundation.

When no IOTA network is specified, it is assumed that the DID is located on the `main` network. This means that the following DIDs will resolve to the same DID Document:
```
did:iota:main:H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV
did:iota:H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV
```

### IOTA-Tag

The IOTA tag references an indexation which resolves to the initial DID Messages. 

#### Generation

The following steps MUST be taken to generate a valid tag:
* Generate an asymmetric keypair using a supported verification method type.
* Hash the public key using `BLAKE2b-256` then encode it using [Base58-BTC](https://tools.ietf.org/id/draft-msporny-base58-01.html).

This public key MUST be embedded into the DID Document (see [CRUD: Create](#create)).

## DID Messages

DID Documents associated with the `did:iota` method consist of a chain of data messages, called "DID messages", published to a Tangle. The Tangle has no understanding of DID messages and acts purely as an immutable database. The chain of DID messages and the resulting DID Document must therefore be validated on the client side. 

A DID message can be part of one of two different message chains, the "Integration Chain" (Int Chain) and the "Differentiation Chain" (Diff Chain). The Integration Chain is a chain of "Integration DID Messages" that contain JSON formatted DID Documents as per the W3C standard for DID. The Diff Chain is a chain of "DID Diff Messages" that contain JSON objects which only list the differences between the previous DID Document and the next state. 

### Previous Message Id

All DID message uploaded to the Tangle, with the exception of the very first DID message that creates the DID, MUST contain a `previousMessageId` field. This field MUST carry the MessageId, an IOTA indexation for a single message, of the previous DID Document that is updated with this DID message. This value SHOULD be used to order DID messages during the resolving procedure. If two or more DID messages reference the same `previousMessageId` an ordering conflict is identified and is resolved using a [deterministic ordering mechanism](#determining-order). 

Example of an IOTA MessageId:
```json
"previousMessageId": "cd8bb7baca6bbfa1de7813bd1753a2de026b6ec75dba8a3cf32c0d4cf6038917"
```

### Signing Keys

DID Documents published to the Tangle must be cryptographically signed. As such, the DID Document MUST include at least one public key with a [capability invocation relationship](https://www.w3.org/TR/did-core/#capability-invocation). Only verification methods with a [capability invocation relationship](https://www.w3.org/TR/did-core/#capability-invocation) are allowed to sign IOTA DID Document updates. It is recommended, for security reasons, not to use signing keys for other purposes as control over them is vital for controlling the identity. It is RECOMMENDED to name the initial verification method `#sign-x`, where `x` is the index of the signing key, which is incremented every time the signing key is updated, starting at index 1.

The initial DID message containing a newly-generated DID Document MUST be signed with the same keypair used to derive its [IOTA-Tag](#iota-tag) (see [CRUD: Create](#create)).

See [Standardized Verification Method Types](#standardized-verification-method-types) for which cryptographic key types are supported.

### Anatomy of Integration DID Messages

An Integration (Int) DID message MUST contain a valid DID Document according to the W3C DID standard. In addition, the message has further restrictions:

* The DID Document MUST contain one or more verification methods capable of signing updates as defined in the [Signing Keys](#signing-keys) section.
* The first DID Document in the chain MUST contain a `verificationMethod` that contains a public key that, when hashed using the `Blake2b-256` hashing function, equals the tag section of the DID. This prevents the creation of conflicting entry messages of the chain by adversaries.
* An Integration DID message must be published to an IOTA Tangle on an index that is generated by the `BLAKE2b-256` of the public key, created in the [generation](#generation) event, encoded in `hex`. 
* Integration DID messages SHOULD contain all cumulative changes from the Diff Chain associated to the last Integration Chain message. Any changes added in the Diff Chain that are not added to the new Integration DID message will be lost. 
* Integration DID messages have at least the following attributes:
    * `previousMessageId` (REQUIRED): This field provides an immutable link to the previous DID document that is updated and is used for basic ordering of the DID messages, creating a chain. The value of `previousMessageId` MUST be a string that contains an IOTA MessageId from the previous DID message it updates, which MUST reference an Int chain message. The field SHOULD be ommited if the DID message is the start of the Int chain, otherwise the field is REQUIRED. Read the [Previous Message Id](#previous-message-id) section for more information. 
    * `proof` (REQUIRED): This field provides a cryptographic proof on the message that proves ownership over the DID Document. The value of the `proof` object MUST contain an object as defined by [Anatomy of the Proof object](#anatomy-of-the-proof-object).

Example of an Integration DID Message:
```json
{
  "id": "did:iota:3mSoeNagPpxkX573xxdxse7qnUSFcQdgU2BkdoqGqznV",
  "capabilityInvocation": [
    {
      "id": "did:iota:3mSoeNagPpxkX573xxdxse7qnUSFcQdgU2BkdoqGqznV#sign-0",
      "controller": "did:iota:3mSoeNagPpxkX573xxdxse7qnUSFcQdgU2BkdoqGqznV",
      "type": "Ed25519VerificationKey2018",
      "publicKeyMultibase": "z5GVUy4njFKpECfEe8Q5CWj1LdmZbMcXJJUipq5sfdkvt"
    }
  ],
  "created": "2021-11-02T21:53:00Z",
  "updated": "2021-11-02T21:53:10Z",
  "previousMessageId": "7f5f281b8aafe0468a21f2c357e0ad7f5fb62a3556de71c22e96f973cedb945b",
  "proof": {
    "type": "JcsEd25519Signature2020",
    "verificationMethod": "#sign-0",
    "signatureValue": "59HqAiMf2pcLRHoMDnN66Boff9CCkMGDosSmsgS7eDoBqsyV4qoSLcyUwyVTbU6Fa5DcGjXoV45e8eye7rVkvYqR"
  }
}
```

### Anatomy of Diff DID Messages

A Differentiation (Diff) DID message does not contain a valid DID Document. Instead, the chain creates a list of changes compared to the Integration DID message that is used as a basis. The Diff DID messages are hosted on a different index on the Tangle, which allows skipping older Diff DID messages during a query, optimizing the client verification speed significantly.  

* A Diff DID message is NOT allowed to add, remove or update any [signing keys](#signing-keys). This must be done via an Integration DID message.
* A Diff DID message must be published to an IOTA Tangle on an index that is generated by the hash, generated by the `BLAKE2b-256` hashing algorithm, of the `previousMessageId` of the latest Integration DID message and encoded in `hex`. 
* Diff DID Messages have at least the following attributes:
    * `id` (REQUIRED): This field helps link the update to a DID. The value of `id` MUST be a string that references the DID that this update applies to. 
    * `previousMessageId` (REQUIRED): This field provides an immutable link to the previous DID document that is updated and is used for basic ordering of the DID messages, creating a chain. The value of `previousMessageId` MUST be a string that contains an IOTA MessageId from the previous DID message it updates, which references either a Diff or Int Chain message. Read the [Previous Message Id](#previous-message-id) section for more information.
    * `diff` (REQUIRED): A Differentiation object containing all the changes compared to the DID Document it references in the `previousMessageId` field. The value of `diff` MUST be an escaped JSON string following the [Anatomy of the Diff object](#anatomy-of-the-diff-object) definition.
    * `proof` (REQUIRED): This field provides a cryptographic proof on the message that proves ownership over the DID Document. The value of the `proof` object MUST contain an object as defined by [Anatomy of the Proof object](#anatomy-of-the-proof-object).

Example of a Diff DID message:
```json
{
  "did": "did:iota:7EhyBxAhFXojqzrKt8Zq7QBvxNZWJJ4xj1mm2QgLmcKj",
  "diff": "{\"authentication\":[{\"index\":0,\"item\":{\"Embed\":{\"id\":\"did:iota:7EhyBxAhFXojqzrKt8Zq7QBvxNZWJJ4xj1mm2QgLmcKj#key-3\",\"key_data\":{\"PublicKeyMultibase\":\"zTJqJAnV387wTUfzq8BVE7iJ9LYs7xJYM4SEF86LkB8E\"}}}}],\"properties\":[{\"c:k\":\"updated\",\"c:v\":\"2021-04-15T10:31:21Z\"}]}",
  "previousMessageId": "9cd2e34c049099246d247ffcf19ba0d54063add9cb7787662b5d51a2a36a8a3b",
  "proof": {
    "type": "JcsEd25519Signature2020",
    "verificationMethod": "#key-2",
    "signatureValue": "G4otnurZMiXwKYpFxZ5Nk99R95FZQ2YSYjztDosaXbyDz8qFrzH8FHbLzFp8doUEPuyHN6CPm58QbAKUqrvq8PV"
  }
}
```

### Anatomy of the Proof object

Following the proof format in the [Verifiable Credential standard](https://www.w3.org/TR/vc-data-model/#proofs-signatures), at least one proof mechanism, and the details necessary to evaluate that, MUST be expressed for a DID Document uploaded to the Tangle. 

The proof object is an embedded proof that contains all information to be verifiable. It contains one or more cryptographic proofs that can be used to detect tampering and verify the authorship of a DID creation or update. It mostly follows LD-Proofs standard.

**Type**

The proof object MUST include a `type` property. This property references a verification method type's signature algorithm, as standardized in the [DID spec registries](https://www.w3.org/TR/did-spec-registries/#verification-method-types) or standardized via the method specification. 

The IOTA Identity implementation currently supports:
- `JcsEd25519Signature2020`

**Verification Method**

The proof object MUST include a `verificationMethod` which references a verification method embedded in the same DID Document. The verification method must be capable of signing DID messages as per the [Signing Keys](#signing-keys) section.

**Signature**

Depending on the verification method, a set of fields are REQUIRED to provide the cryptographic proof of the DID Document. For example, the `JcsEd25519Signature2020` method has a `signatureValue` field. 

Example `proof` using the `JcsEd25519Signature2020` method:
```json
"proof": {
    "type": "JcsEd25519Signature2020",
    "verificationMethod": "did:iota:GzXeqBXGCbuebiFtKo4JDNo6CmYmGbqxyh2fDVKadiBG#authentication",
    "signatureValue": "3fLtv3KUU4T5bHNLprV3UQ2Te3bcRZ9uUYSFouEA7fmYthieV35NNLqbKUu8t2QmzYgnfp1KMzCqPzGNi3RjU822"
}
```

### Anatomy of the Diff object

The `diff` object MUST contain all the differences between the previous DID Document and the current DID Document. The differentiation is formatted as an escaped JSON object, that includes the differences between the two DID Document objects. Exact details of how this is generated will be added later. 

Example `diff` of adding an `authentication` key and changing the `updated` field:
```json
{
  "diff": "{\"authentication\":[{\"index\":0,\"item\":{\"Embed\":{\"id\":\"did:iota:7EhyBxAhFXojqzrKt8Zq7QBvxNZWJJ4xj1mm2QgLmcKj#key-3\",\"key_data\":{\"PublicKeyMultibase\":\"zTJqJAnV387wTUfzq8BVE7iJ9LYs7xJYM4SEF86LkB8E\"}}}}],\"properties\":[{\"c:k\":\"updated\",\"c:v\":\"2021-04-15T10:31:21Z\"}]}"
} 
```

## CRUD Operations

Create, Read, Update and Delete (CRUD) operations that change the DID Documents are to be submitted to an IOTA Tangle in order to be publicly avaliable. They will either have to be a valid Int DID message or Diff DID message, submitted on the correct index of the identity. 

### Create

To generate a new DID, the method described in [generation](#generation) must be followed. A basic DID Document must be created that includes the public key used in the DID creation process as a `verificationMethod` with a capability invocation verification relationship. This DID Document must be formatted as an Integration DID message, signed using the same keypair used to generate the tag, and published to an IOTA Tangle on the index generated out of the public key used in the DID creation process. 

### Read

To read the latest DID Document associated with a DID, the following steps are to be performed:
1. Query all the Integration DID messages from the index, which is the `tag` part of the DID.
2. Order the messages based on `previousMessageId` linkages. See [Determining Order](#determining-order) for more details.
3. Validate the first Integration DID message containing a verification method with a public key that, when hashed using the `BLAKE2b-256` hashing algorithm, equals the `tag` field of the DID as per [generation](#generation). This first Integration DID message MUST also contain a valid signature referencing the same verification method.
4. Verify the signatures of all the DID messages. Signatures must be created using a public key available in the previous DID message linked to a verification method capable of signing DID messages. See [Signing Keys](#signing-keys).
5. Ignore any messages that are not signed correctly, afterwards ignore any messages that are not first in the ordering for their specific location in the chain.
6. Query all the Diff DID messages from the index, generated by the MessageId from the last valid Integration DID message, hashed using `Blake2b-256` and encoded in `hex`.
7. Order messages and validate signatures in a similar manner to steps 2, 4 and 5 above. The first valid Diff DID message MUST have a `previousMessageId` referencing the `messageId` of the last Integration DID message. 
8. Ignore Diff DID messages with illegal operations such as removing or updating a signing key.
9. Apply all valid Diff updates to the state generated from the Integration DID messages. This will result in the latest DID Document.

#### Determining Order

To determine the order of any DID messages, the following steps are to be performed:
1. Order is initially established by recreating the chain based on the `previousMessageId` linkages. 
   1. For Int DID messages, the one with no `previousMessageId` is first.
   2. For Diff DID messages, the one with a `previousMessageId` referencing the IOTA MessageId of the corresponding Integration DID message is first.
2. When two or more Messages compete, an order must be established between them.
3. To determine the order, check which milestone confirmed the messages.
4. If multiple messages are confirmed by the same milestone, we order based on the IOTA MessageId with alphabetical ordering.

### Update

In order to update a DID Document, either an Integration or a Diff DID message needs to be generated. It is RECOMMENDED to use only Integration DID messages if the DID Document is updated very infrequently and it is expected to never go beyond 100 updates in the lifetime of the DID. If that is not the case, it is RECOMMENDED to use as many Diff DID messages instead with a maximum of around 100 updates per Diff chain. 

#### Creating an Integration DID message

An Integration DID message is unrestricted in its operations and may add or remove any fields to the DID Document. In order to query the DID Document, every Integration DID message must be processed, therefore it is RECOMMENDED to reduce the usage of these messages unless the DID Document is updated very infrequently. 

In order to create a valid Integration DID message, the following steps are to be performed:
1. Create a new DID Document that contains all the new target state. This SHOULD include the new desired changes and all the changes inside the previous Diff Chain, otherwise these changes are lost!
2. Retrieve the IOTA MessageId from the previous Integration DID message and a keypair for signing the DID Document.
3. Set the `previousMessageId` field to the IOTA MessageId value.
4. Create a `proof` object referencing the public key and signature suite from a verification method in the DID Document able to sign updates as per the [Signing Keys](#signing-keys) section.
5. Create a cryptographic signature using the same keypair and add the result to the appropriate field(s) inside the `proof` object.

#### Creating a Diff DID message

A Differentiation DID message is restricted in its usage. It may not update any signing keys that are used in the Diff chain. If this is desired, it is REQUIRED to use an Integretation DID message. If the current Diff chain becomes too long (currently RECOMMENDED to end at a length of 100), it is RECOMMENDED to use a single Integration DID message to reset its length.

In order to create a valid Integration DID message, the following steps are to be performed:
1. Create and serialize a `diff` JSON object that contains all the changes. 
2. Set the `did` field to the DID value that this update applies to.
3. Retrieve the IOTA MessageId from the previous Diff chain message, or Integration DID message if this message is the first in the Diff chain. In addition, retrieve a keypair for signing the DID Document.
4. Set the `previousMessageId` field to the IOTA MessageId value.
5. Create a `proof` object referencing the public key and signature suite from a verification method in the DID Document able to sign updates as per the [Signing Keys](#signing-keys) section.
6. Create a cryptographic signature using the same keypair and add the result to the appropriate field(s) inside the `proof` object.

### Delete

In order to deactivate a DID document, a valid Integration DID message must be published that removes all content from a DID Document, effectively deactivating the DID Document. Keep in mind that this operation is irreversible.

## IOTA Identity standards

The `did:iota` method is implemented in the [IOTA Identity framework](https://github.com/iotaledger/identity.rs). This framework supports a number of operations that are standardized, some are standardized across the SSI community, and some are the invention of the IOTA Foundation. 

### Standardized Verification Method Types

We support two different Verification Method Types. Verification methods that can be used for signing DID Documents, and verification methods that are only used for signing [W3C standardized Verifiable Credentials](https://www.w3.org/TR/vc-data-model/). This set differs as the IOTA Identity implements revocation of Verifiable Credentials through public key removal, which requires every credential to be signed by a different keypair. We create collection of keypairs in a Merkle Tree in order to save space in the DID Document.

Verification Methods that can be used to sign DID Documents and do other repeatable activities:
* `Ed25519VerificationKey2018` to create a `JcsEd25519Signature2020`.

Verification Methods that can be used to sign Verifiable Credentials:
* `MerkleKeyCollection2021` to create a `MerkleKeySignature2021`.

### Revocation

As mentioned above, revocation of Verifiable Credentials is done through revoking public keys in the IOTA Identity framework. IOTA Identity has a highly scalable solution since some identities might sign and want to revoke thousands if not millions of Verifiable Credentials. It is also GDPR compliant, leaving no trace, not even a hash, of a verifiable credential on the Tangle. Below will be a brief overview of how this mechanism works, but you may read all the details in the [MerkleKeyCollection standardization document](./merkle_key_collection.md). 

#### Key Collections

Instead of storing individual public keys in a DID Document, IOTA Identity introduces the `MerkleKeyCollection2021` verification method. It supports a REQUIRED `publicKeyMultibase` field that MUST contain the top hash of a Merkle Tree. In this Merkle Tree all the individual leaves are public keys using the signature algorithm of choice and digest algorithm of choice for the Merkle Tree process. This process allows the creation of millions of public keys within a single verification method and without bloating the DID Document. Specific info such as the maximum depth of the Merkle Tree, supported signature algorithms and digest algorithms can be found [in the specification document](./merkle_key_collection.md). 

#### Verifiable Credential Proofs

In addition to the normal signature, a `MerkleKeySignature2021` requires additional proof data to validate the signature's origin and validity. The public key itself needs to be revealed inside the `signatureValue` field, but also the individual hashes inside the Merkle Tree and their relative location in the path to create a valid `Proof of Inclusion`. 

#### Revocation List

In order to revoke a public key, and therefore any Verifiable Credential or other statements, the DID Document must be updated with a revocation list. The REQUIRED `revocation` field is introduced inside the `MerkleKeyCollection2021` verification method, which lists the indices from the leaves of the Merkle Tree that are revoked. These indices are further compressed via [Roaring Bitmaps](https://roaringbitmap.org/).

### Standardized Services

The IOTA Identity framework also standardized certain `services` that are embedded in the DID Document. It is RECOMMENDED to implement these when implementing the `did:iota` method. 

Currently standardized `services`:
* Nothing yet. 

## Security Considerations

The `did:iota` method is implemented on the [IOTA Tangle](https://iota.org), a public permissionless and feeless Distributed Ledger Technology (DLT), making it resistant against almost all censorship attack vectors. Up until the `Coordicide` update for the IOTA network, a reliability on the coordinator exists for resolving ordering conflicts. This has a minor censorship possibility, that, in the worst case, can prevent ordering conflicts from resolving to a DID. However, these can only be published by the owner of the private key and therefore does not constitute a usable attack vector. Lastly, a node may decide to censor DID messages locally, however a user can easily use another node. 

Since DID messages are always to be signed and the 'chain of custody' of the signing key can be traced throughout the identity lifespan, replay, message insertion, deletion, modification and man-in-the-middle attacks are prevented.

### Stateless Identities

Unlike for-purpose blockchains or Smart Contract based DID methods, the IOTA Tangle does not track and store the state of DID Document. This prevents dusting attacks against the nodes. However, the client that resolves the DID Document has the responsibility to always validate the entire history of the DID Document as to validate the 'chain of custody' of the signing keys. If a client does not do this, identity hijacking is trivially possible. The IOTA Identity framework, which implements the `did:iota` method, provides an easy-to-use client-side validation implementation. 

### Snapshotting

IOTA allows feeless data and value messages. As such, it has a large history of messages amounting to several TBs at the time of writing. Most nodes 'snapshot' (forget/delete) older transactions, while they keep the UTXOs stored in the ledger. The snapshot settings are local, therefore all nodes may store a different length of history. As such, older DID messages would not be avaliable at every node. Since the entire history of the DID Document is required for client-side validation, this may become problematic. It is currently recommended to either use your own node that does not snapshot, or use the [Chronicle Permanode](https://github.com/iotaledger/chronicle.rs), which keeps the entire history of the Tangle. This is not a longterm scalable solution, which is why other methods for either keeping state or selective storage are considered. 

### Denial of Service Attacks

There is little to no barrier for users to send any message to the Tangle. While this is a great feature of IOTA, it has its drawbacks in terms of spam. Anyone can post messages on the index of an Identity and therefore decrease the query speed. To reduce a user's own load on their identity verification speed, the Diff chain was introduced. Other messages that are spammed are identified and dropped as early as possible in the resolution process without triggering any errors or warnings. These are, for example, random data messages or incorrectly signed DID messages. 

IOTA nodes provide pagination for more then 100 messages on an index, requiring multiple queries for identities with more messages. Since the queries are the bottleneck in the resolution process, it is recommended to run an IOTA node in a nearby location if fast verification is required for the use case. Verification may, in the future, also be outsourced to nodes directly, to reduce the effect of spam attacks. If an identity is significantly spammed, it might be best to create a new identity. 

### Quantum Computer Threats

The `did:iota` method is not more vulnerable to quantum computers than other DID methods. The IOTA Identity framework currently utilizes elliptic curve based cryptographic suites, however adding support for quantum secure cryptographic suites in the future is very easy. The `MerkleKeyCollection2021` verification method is quantum secure in the sense that public keys are only revealed to the holders and verifiers of the Verifiable Credentials, keeping the exposure to this very limited. 

### Private Key Management

All private keys or seeds used for the `did:iota` method should be equally well protected by the users. The signing key is especially important as it controls how keys are added or removed, providing full control over the identity. The IOTA Identity framework utilizes the [Stronghold project](https://github.com/iotaledger/stronghold.rs), a secure software implementation isolating digital secrets from exposure to hacks or leaks. Developers may choose to add other ways to manage the private keys in a different manner.  

## Privacy Considerations

### Personal Identifiable Information

The public IOTA Tangle networks are immutable networks. This means that once something is uploaded, it can never be completely removed. That directly conflicts with certain privacy laws such as GDPR, which have a 'right-to-be-forgotten' for Personal Identifiable Information (PII). As such, users should NEVER upload any PII to the Tangle, including inside DID Documents. The IOTA Identity framework allows Verifiable Credentials to be published to the Tangle directly, however this feature should only be utilized by Identity for Organisation and Identity for Things. 

### Correlation Risks

As with any DID method, identities can be linked if they are used too often and their usage somehow becomes public. IOTA provides a simple solution for this problem: as creating identities is completely feeless, it is recommended to make new identities on a per interaction basis (Pairwise DIDs). The IOTA Identity framework will provide support for this in the future. 
