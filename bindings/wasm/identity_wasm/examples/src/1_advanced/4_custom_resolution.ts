import { CoreDocument, IotaDocument, Resolver } from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL } from "../util";

type KeyDocument = { customProperty: String } & CoreDocument;

function isKeyDocument(doc: object): doc is KeyDocument {
    return "customProperty" in doc;
}

/** Demonstrates how to set up a resolver using custom handlers.
 */
export async function customResolution() {
    // Set up a handler for resolving Ed25519 did:key
    const keyHandler = async function(didKey: string): Promise<KeyDocument> {
        // statically return DID document, implement custom resolution here
        let document = JSON.parse(`
        {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://w3id.org/security/suites/x25519-2020/v1"
            ],
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "verificationMethod": [{
                "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "assertionMethod": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "capabilityDelegation": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "capabilityInvocation": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "keyAgreement": [{
                "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "publicKeyMultibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
            }]
        }`);

        // for demo purposes we'll just inject the custom property into a core document
        // to create a new KeyDocument instance
        const doc = CoreDocument.fromJSON(document) as KeyDocument;
        doc.customProperty = "foobar";
        return doc;
    };

    // create new clients and create new account
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();
    const storage = getMemstorage();
    const identityClient = await getFundedClient(storage);
    const [unpublished] = await createDocumentForNetwork(storage, network);

    // create new identity for this account and publish document for it, DID of it will be resolved later on
    const { output: identity } = await identityClient
        .createIdentity(unpublished)
        .finish()
        .buildAndExecute(identityClient);
    const did = identity.didDocument().id();

    // Construct a Resolver capable of resolving the did:key and iota methods.
    let handlerMap: Map<string, (did: string) => Promise<IotaDocument | KeyDocument>> = new Map();
    handlerMap.set("key", keyHandler);

    const resolver = new Resolver<IotaDocument | KeyDocument>(
        {
            client: identityClient,
            handlers: handlerMap,
        },
    );

    // A valid Ed25519 did:key value taken from https://w3c-ccg.github.io/did-method-key/#example-1-a-simple-ed25519-did-key-value.
    const didKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    // Resolve didKey into a DID document.
    const didKeyDoc = await resolver.resolve(didKey);

    // Resolve the DID we created on the IOTA network.
    const didIotaDoc = await resolver.resolve(did.toString());

    // Check that the types of the resolved documents match our expectations:

    if (isKeyDocument(didKeyDoc)) {
        console.log("Resolved DID Key document:", JSON.stringify(didKeyDoc, null, 2));
        console.log(`Resolved DID Key document has a custom property with the value '${didKeyDoc.customProperty}'`);
    } else {
        throw new Error(
            "the resolved document type should match the output type of keyHandler",
        );
    }

    if (didIotaDoc instanceof IotaDocument) {
        console.log("Resolved IOTA DID document:", JSON.stringify(didIotaDoc, null, 2));
    } else {
        throw new Error(
            "the resolved document type should match IotaDocument",
        );
    }
}
