IOTA Identity
===

## About
This crate provides the core data structures for the [IOTA DID Method Specification](https://docs.iota.org/iota-identity). It provides interfaces for publishing and resolving DID Documents according to the IOTA DID Method Specification.

## Running the tests
You can run the tests as usual with:

```sh
cargo test
```

The e2e should be run against a [local network](https://docs.iota.org/developer/getting-started/local-network), as this makes funding way more easy, as the local faucet can be used deliberately.

### Running the tests with active-address-funding
When you're not running the tests locally, you might notice some restrictions in regards of interactions with the faucet. The current e2e test setup creates new test accounts for every test to avoid test pollution, but those accounts request funds from a faucet. That faucet might have restrictions on how much funds an IP can request in a certain time range. For example, this might happen when trying to run the tests against `devnet`.

As we want to verify that our API works as expected on this environment as well, a toggle has been added to change the behavior in the tests to not request the faucet for funds, but use the active account of the IOTA CLI to send funds to new test users. This is not the default test behavior and should only be used in edge cases, as it comes with a few caveats, that might not be desired to have in the tests:

- The active address must be well funded, the current active-address-funding transfers 500_000_000 NANOS to new test accounts. So make sure, this account has enough funds to support a few 2e2 tests with one or more accounts.
- The tests will take longer, as they have to be run sequentially to avoid collisions between the fund sending transactions.

You can run a tests with active-address-funding with:

```sh
IOTA_IDENTITY_FUND_WITH_ACTIVE_ADDRESS=true cargo test -- --test-threads=1
```

To check your active account's funds, you can use

```sh
iota client gas
```
