/** Supported types for the JSON Web Key `kty` property.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types) */
export const enum JwkType {
    /** Elliptic Curve. */
    Ec = "EC",
    /** RSA. */
    Rsa = "RSA",
    /** Octet sequence. */
    Oct = "oct",
    /** Octet string key pairs. */
    Okp = "OKP",
    /** Algorithm key pair. */
    Akp = "AKP",
}
