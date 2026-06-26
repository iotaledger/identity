export {};

import { CoreDID, CoreDocument, IotaDID, IotaDocument, IToCoreDocument, Resolver } from "../node";
import assert = require("assert");

const fooDoc = CoreDocument.fromJSON({
    "id": "did:foo:586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
    "verificationMethod": [
        {
            "id": "did:foo:586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5#root",
            "controller": "did:foo:586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "z586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
        },
    ],
});
const iotaDoc: IotaDocument = IotaDocument.fromJSON({
    "doc": {
        "id": "did:iota:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "verificationMethod": [
            {
                "id": "did:iota:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#issuerKey",
                "controller": "did:iota:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "type": "Ed25519VerificationKey2018",
                "publicKeyMultibase": "zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z",
            },
        ],
    },
    "meta": {
        "created": "2022-08-31T09:33:31Z",
        "updated": "2022-08-31T09:33:31Z",
    },
});
const barDoc: CoreDocument = CoreDocument.fromJSON({
    "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
    "verificationMethod": [
        {
            "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr#root",
            "controller": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "zHyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
        },
    ],
});

class MockFooDocument {
    inner: CoreDocument;
    constructor(inner: CoreDocument) {
        this.inner = inner;
    }

    toCoreDocument(): CoreDocument {
        return this.inner;
    }
}

describe("Resolver", function() {
    describe("#resolving", function() {
        it("should resolve successfully configured correctly", async () => {
            // mock method handlers
            const resolveDidIota = async function(did_input: string) {
                const parsedDid: IotaDID = IotaDID.parse(did_input);
                if (iotaDoc.id().toString() == parsedDid.toString()) {
                    return iotaDoc;
                } else {
                    throw new Error(`could not resolve did ${did_input}`);
                }
            };

            const resolveDidFoo = async function(did_input: string) {
                const parsedDid: CoreDID = CoreDID.parse(did_input);
                if (fooDoc.id().toString() == parsedDid.toString()) {
                    let doc = new MockFooDocument(fooDoc);
                    return doc;
                } else {
                    throw new Error(`could not resolve did ${did_input}`);
                }
            };

            const resolveDidBar = async function(did_input: string) {
                const parsedDid: CoreDID = CoreDID.parse(did_input);
                if (barDoc.id().toString() == parsedDid.toString()) {
                    return barDoc;
                } else {
                    throw new Error(`could not resolve did ${did_input}`);
                }
            };

            let handlerMap: Map<string, (did: string) => Promise<CoreDocument | IToCoreDocument>> = new Map();
            handlerMap.set("iota", resolveDidIota);
            handlerMap.set("foo", resolveDidFoo);
            handlerMap.set("bar", resolveDidBar);

            const resolver = new Resolver({
                handlers: handlerMap,
            });

            const [resolvedBarDoc, resolvedIotaDoc, resolvedFooDoc] = await Promise.all([
                resolver.resolve(barDoc.id().toString()),
                resolver.resolve(iotaDoc.id().toString()),
                resolver.resolve(fooDoc.id().toString()),
            ]);

            assert.deepStrictEqual(barDoc.toJSON(), (resolvedBarDoc as CoreDocument).toJSON());
            assert.deepStrictEqual(iotaDoc.toJSON(), (resolvedIotaDoc as IotaDocument).toJSON());
            assert.deepStrictEqual(fooDoc.toJSON(), (resolvedFooDoc as MockFooDocument).toCoreDocument().toJSON());

            let dids = [barDoc.id().toString(), iotaDoc.id().toString(), fooDoc.id().toString(),
                iotaDoc.id().toString()];
            let documents = await resolver.resolveMultiple(dids);

            assert.equal(documents.length, 4);
            assert.deepStrictEqual(barDoc.toJSON(), (documents[0] as CoreDocument).toJSON());
            assert.deepStrictEqual(iotaDoc.toJSON(), (documents[1] as IotaDocument).toJSON());
            assert.deepStrictEqual(fooDoc.toJSON(), (documents[2] as MockFooDocument).toCoreDocument().toJSON());
            assert.deepStrictEqual(iotaDoc.toJSON(), (documents[3] as IotaDocument).toJSON());
        });

        it("should fail resolution when configured incorrectly", async () => {
            // setup mock handlers returning DID documents from other methods
            const resolveDidIotaMisconfigured = async function(_did_input: string) {
                return fooDoc;
            };

            const resolveDidFooMisconfigured = async function(_did_input: string) {
                return barDoc;
            };

            const resolveDidBarMisconfigured = async function(did_input: string) {
                return iotaDoc;
            };

            let handlerMap: Map<string, (did: string) => Promise<IotaDocument | CoreDocument>> = new Map();
            handlerMap.set("iota", resolveDidIotaMisconfigured);
            handlerMap.set("foo", resolveDidFooMisconfigured);
            handlerMap.set("bar", resolveDidBarMisconfigured);

            const resolver = new Resolver({
                handlers: handlerMap,
            });

            const promises = [
                resolver.resolve(iotaDoc.id().toString()),
                resolver.resolve(fooDoc.id().toString()),
                resolver.resolve(barDoc.id().toString()),
            ];

            for (const promise in promises) {
                try {
                    await promise;
                } catch (e) {
                    if (e instanceof Error) {
                        assert.equal("HandlerError", e.name);
                        return;
                    } else {
                        throw new Error(
                            "the incorrectly configured resolver did not throw the expected error when resolving",
                        );
                    }
                }
            }
        });
    });
});
