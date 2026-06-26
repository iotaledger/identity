/** Supported Elliptic Curves.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve) */
export const enum EdCurve {
    /** Ed25519 signature algorithm key pairs. */
    Ed25519 = "Ed25519",
    /** Ed448 signature algorithm key pairs. */
    Ed448 = "Ed448",
}
