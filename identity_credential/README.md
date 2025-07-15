# IOTA Identity - Credentials

This crate contains types representing verifiable credentials and verifiable presentations as defined in the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).

Convenience methods for validating [Verifiable Credentials](https://docs.iota.org/iota-identity/explanations/verifiable-credentials) and [Verifiable Presentations](https://docs.iota.org/iota-identity/explanations/verifiable-presentations) are also provided:

- [`JwtCredentialValidator`](crate::validator::JwtCredentialValidator)
- [`JwtPresentationValidator`](crate::validator::JwtPresentationValidator)

The [IOTA Identity Framework Docs](https://docs.iota.org/iota-identity) offers a comprehensive overview of verifiable credentials and presentations along with practical demonstrations and examples showcasing the capabilities of this crate in creating and validating them.
