import * as assert from "assert";
import { SdObjectDecoder, SdObjectEncoder } from "../node";

describe("sd-jwt-payload", function() {
    describe("#encoder", function() {
        it("should work", async () => {
            let obj = {
                "sub": "user_42",
                "given_name": "John",
                "family_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "+1-202-555-0101",
                "phone_number_verified": true,
                "address": {
                    "street_address": "123 Main St",
                    "locality": "Anytown",
                    "region": "Anystate",
                    "country": "US",
                },
                "birthdate": "1940-01-01",
                "updated_at": 1570000000,
                "nationalities": [
                    "US",
                    "DE",
                ],
            };

            let encoder = new SdObjectEncoder(obj);
            let emailDisclosure = encoder.conceal("/email", "tstsalt");
            console.log(emailDisclosure);
            assert.deepStrictEqual(emailDisclosure.claimName(), "email");
            assert.deepStrictEqual(emailDisclosure.claimValue(), "johndoe@example.com");
            assert.deepStrictEqual(emailDisclosure.salt(), "tstsalt");
            assert.deepStrictEqual(
                emailDisclosure.disclosure(),
                "WyJ0c3RzYWx0IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
            );

            let disclosures = [
                emailDisclosure.toEncodedString(),
                encoder.conceal("/address/street_address").toEncodedString(),
                encoder.conceal("/nationalities/0").toEncodedString(),
            ];
            encoder.addSdAlgProperty();
            encoder.addDecoys("", 3);
            let encoded = encoder.encodeToObject();
            assert.equal(encoded._sd.length, 4);

            let decoder = new SdObjectDecoder();
            let decoded = decoder.decode(encoded, disclosures);
            assert.deepStrictEqual(obj, decoded);
        });
    });
});
