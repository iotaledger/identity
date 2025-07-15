/** Supported algorithms for the JSON Web Key `key_ops` property.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations) */
export const enum JwkOperation {
    /** Compute digital signature or MAC. */
    Sign = "sign",
    /** Verify digital signature or MAC. */
    Verify = "verify",
    /** Encrypt content. */
    Encrypt = "encrypt",
    /** Decrypt content and validate decryption, if applicable. */
    Decrypt = "decrypt",
    /** Encrypt key. */
    WrapKey = "wrapKey",
    /** Decrypt key and validate decryption, if applicable. */
    UnwrapKey = "unwrapKey",
    /** Derive key. */
    DeriveKey = "deriveKey",
    /** Derive bits not to be used as a key. */
    DeriveBits = "deriveBits",
}
