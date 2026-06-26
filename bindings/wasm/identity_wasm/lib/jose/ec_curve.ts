/** Supported Elliptic Curves.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve) */
export const enum EcCurve {
    /** P-256 Curve. */
    P256,
    /** P-384 Curve. */
    P384,
    /** P-521 Curve. */
    P521,
    /** SECG secp256k1 curve. */
    Secp256K1,
}
