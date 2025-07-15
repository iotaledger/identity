// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    CoreDID,
    Credential,
    DIDUrl,
    DomainLinkageConfiguration,
    Duration,
    EdDSAJwsVerifier,
    IotaDID,
    IotaDocument,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtDomainLinkageValidator,
    LinkedDomainService,
    Timestamp,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL, TEST_GAS_BUDGET } from "../util";

/**
 * Demonstrates how to link a domain and a DID and verify the linkage.
 */
export async function domainLinkage() {
    // create new clients and create new account
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();
    const storage = getMemstorage();
    const identityClient = await getFundedClient(storage);
    const [unpublished, vmFragment1] = await createDocumentForNetwork(storage, network);

    // create new identity for this account and publish document for it
    const { output: identity } = await identityClient
        .createIdentity(unpublished)
        .finish()
        .buildAndExecute(identityClient);
    const document = identity.didDocument();
    const did = document.id();

    // =====================================================
    // Create Linked Domain service
    // ====================================================

    let domainFoo = "https://foo.example.com";
    let domainBar = "https://bar.example.com";

    // Create a Linked Domain Service to enable the discovery of the linked domains through the DID Document.
    // This is optional since it is not a hard requirement by the spec.
    let serviceUrl: DIDUrl = did.clone().join("#domain_linkage");
    let linkedDomainService: LinkedDomainService = new LinkedDomainService({
        id: serviceUrl,
        domains: [domainFoo, domainBar],
    });
    document.insertService(linkedDomainService.toService());
    const controllerToken = await identity.getControllerToken(identityClient);
    await identity.updateDidDocument(document, controllerToken!).buildAndExecute(identityClient);

    let updatedDidDocument = identity.didDocument();
    console.log("Updated DID document:", JSON.stringify(updatedDidDocument, null, 2));

    // =====================================================
    // Create DID Configuration resource
    // =====================================================

    // Now the DID Document contains a service that includes the domains.
    // To allow a bidirectional linkage, the domains must link to the DID. This is
    // done by creating a `DID Configuration Resource` that includes a `Domain Linkage Credential`
    // and can be made available on the domain.

    // Create the Domain Linkage Credential.
    let domainLinkageCredential: Credential = Credential.createDomainLinkageCredential({
        issuer: document.id(),
        origin: domainFoo,
        expirationDate: Timestamp.nowUTC().checkedAdd(Duration.weeks(10))!,
    });

    // Sign the credential.
    const credentialJwt = await document.createCredentialJwt(
        storage,
        vmFragment1,
        domainLinkageCredential,
        new JwsSignatureOptions(),
    );

    // Create the DID Configuration Resource which wraps the Domain Linkage credential.
    let configurationResource: DomainLinkageConfiguration = new DomainLinkageConfiguration([credentialJwt]);

    // The DID Configuration resource can be made available on `https://foo.example.com/.well-known/did-configuration.json`.
    let configurationResourceJson = configurationResource.toJSON();
    console.log("Configuration Resource:", JSON.stringify(configurationResourceJson, null, 2));

    // Now the DID Document links to the Domains through the service, and the Foo domain links to the DID
    // through the DID Configuration resource. A bidirectional linkage is established.
    // Note however that bidirectionality is not a hard requirement. It is valid to have a Domain Linkage
    // credential point to a DID, without the DID having a service that points back.

    // =====================================================
    // Verification can start from two different places.
    // The first case answers the question "What DID is this domain linked to?"
    // while the second answers "What domain is this DID linked to?".
    // ====================================================

    // =====================================================
    // → Case 1: starting from domain
    // =====================================================

    // Fetch the DID Configuration resource (For example using the Fetch API).
    // Note that according to the specs, the DID Configuration resource must exist
    // at the origin's root, well-known Resource directory.
    const _configurationUrl = `${domainFoo}/.well-known/did-configuration.json")`;

    // But since the DID Configuration
    // resource isn't available online in this example, we will simply use the JSON.
    let fetchedConfigurationResource = DomainLinkageConfiguration.fromJSON(configurationResource);

    // Retrieve the issuers of the Domain Linkage Credentials which correspond to the possibly linked DIDs.
    // Note that in this example only the first entry in the credential is validated.
    let issuers: Array<CoreDID> = fetchedConfigurationResource.issuers();
    const issuerDocument: IotaDocument = await identityClient.resolveDid(IotaDID.parse(issuers[0].toString()));

    // Validate the linkage between the Domain Linkage Credential in the configuration and the provided issuer DID.
    // Validation succeeds when no error is thrown.
    new JwtDomainLinkageValidator(new EdDSAJwsVerifier()).validateLinkage(
        issuerDocument,
        fetchedConfigurationResource,
        domainFoo,
        new JwtCredentialValidationOptions(),
    );

    // =====================================================
    // → Case 2: starting from a DID
    // =====================================================

    const didDocument: IotaDocument = await identityClient.resolveDid(did);

    // Get the Linked Domain Services from the DID Document.
    let linkedDomainServices: LinkedDomainService[] = didDocument
        .service()
        .filter(service => LinkedDomainService.isValid(service))
        .map(service => LinkedDomainService.fromService(service));

    // Get the domains included in the Linked Domain Service.
    // Note that in this example only the first entry in the service is validated.
    let domains: string[] = linkedDomainServices[0].domains();

    // Fetch the DID Configuration resource (For example using the Fetch API).
    // Note that according to the specs, the DID Configuration resource must exist
    // at the origin's root, Well-Known Resource directory.
    const __configurationUrl = `${domains[0]}/.well-known/did-configuration.json")`;

    // But since the DID Configuration
    // resource isn't available online in this example, we will simply use the JSON.
    fetchedConfigurationResource = DomainLinkageConfiguration.fromJSON(configurationResource);

    // Validate the linkage between the Domain Linkage Credential in the configuration and the provided issuer DID.
    // Validation succeeds when no error is thrown.
    new JwtDomainLinkageValidator(new EdDSAJwsVerifier()).validateLinkage(
        didDocument,
        fetchedConfigurationResource,
        domains[0],
        new JwtCredentialValidationOptions(),
    );

    console.log("Successfully validated Domain Linkage!");
}
