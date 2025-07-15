/** Supported algorithms for the JSON Web Signatures `alg` claim.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms) */
export const enum JwsAlgorithm {
    /** HMAC using SHA-256 */
    HS256 = "HS256",
    /** HMAC using SHA-384 */
    HS384 = "HS384",
    /** HMAC using SHA-512 */
    HS512 = "HS512",
    /** RSASSA-PKCS1-v1_5 using SHA-256 */
    RS256 = "RS256",
    /** RSASSA-PKCS1-v1_5 using SHA-384 */
    RS384 = "RS384",
    /** RSASSA-PKCS1-v1_5 using SHA-512 */
    RS512 = "RS512",
    /** RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
    PS256 = "PS256",
    /** RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
    PS384 = "PS384",
    /** RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
    PS512 = "PS512",
    /** ECDSA using P-256 and SHA-256 */
    ES256 = "ES256",
    /** ECDSA using P-384 and SHA-384 */
    ES384 = "ES384",
    /** ECDSA using P-521 and SHA-512 */
    ES512 = "ES512",
    /** ECDSA using secp256k1 curve and SHA-256 */
    ES256K = "ES256K",
    /** No digital signature or MAC performed */
    NONE = "none",
    /** EdDSA signature algorithms */
    EdDSA = "EdDSA",
    /** ML-DSA-44 */
    MLDSA44 = "ML-DSA-44",
    /** ML-DSA-65 */
    MLDSA65 = "ML-DSA-65",
    /** ML-DSA-87 */
    MLDSA87 = "ML-DSA-87",
    /** ML-DSA-44 in hybrid signature*/
    IdMldsa44Ed25519 = "id-MLDSA44-Ed25519",
    /** ML-DSA-65 in hybrid signature*/
    IdMldsa65Ed25519 = "id-MLDSA65-Ed25519",

}
