/** Supported algorithms for the JSON Web Key `use` property.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-use) */
export const enum JwkUse {
    /** Digital Signature or MAC. */
    Signature = "sig",
    /** Encryption. */
    Encryption = "enc",
}
