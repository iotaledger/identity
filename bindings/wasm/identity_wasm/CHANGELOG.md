# Changelog

## [wasm-v1.8.0-beta.2](https://github.com/iotaledger/identity/tree/wasm-v1.8.0-beta.2) (2025-12-18)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.7.0-beta.1...wasm-v1.6.0-beta.10)

### Patch

- Bump `iota-interaction` to version `0.10.0` [\#1756](https://github.com/iotaledger/identity/pull/1756)

## [wasm-v1.8.0-beta.1](https://github.com/iotaledger/identity/tree/wasm-v1.8.0-beta.1) (2025-12-07)

### Added

- Support for [VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) and JWT encoding 
  [\#1738](https://github.com/iotaledger/identity/pull/1738)

### Patch

- Fix `IotaDID.toObjectId` and `IotaDID.fromObjectId` [\#1747](https://github.com/iotaledger/identity/pull/1747)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.8.0-beta.1...v1.7.0-beta.1)

## [wasm-v1.7.0-beta.1](https://github.com/iotaledger/identity/tree/wasm-v1.7.0-beta.1) (2025-10-14)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.7.0-beta.1...wasm-v1.6.0-beta.10)

### Added

- Post Quantum and hybrid traditional / Post Quantum signatures for VCs and VPs [\#1625](https://github.com/iotaledger/identity/pull/1625)
- Enhanced support for Linked Verifiable Presentations [\#1729](https://github.com/iotaledger/identity/pull/1729)
- `DIDJwk.new` [\#1725](https://github.com/iotaledger/identity/pull/1725)
- `IdentityClientReadOnly.didsControlledBy` and `IdentityClient.controlledDids` [\#1708](https://github.com/iotaledger/identity/pull/1708)

## [wasm-v1.5.1](https://github.com/iotaledger/identity/tree/wasm-v1.5.1) (2025-04-16)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.5.0...wasm-v1.5.1)

### Patch

- Update domain linkage validation for multiple creds by same issuer [\#1611](https://github.com/iotaledger/identity/pull/1611)
- Credential's context is a set even when a single context value is present [\#1570](https://github.com/iotaledger/identity/pull/1570)

## [wasm-v1.5.0](https://github.com/iotaledger/identity/tree/wasm-v1.5.0) (2025-01-20)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.4.0...wasm-v1.5.0)

### Added

- SD-JWT VC implementation [\#1413](https://github.com/iotaledger/identity/pull/1413)

### Patch

- Support %-encoded characters in DID URL [\#1496](https://github.com/iotaledger/identity/pull/1496)
- fix: serialization of status list [\#1423](https://github.com/iotaledger/identity/pull/1423)

## [wasm-v1.4.0](https://github.com/iotaledger/identity/tree/wasm-v1.4.0) (2024-09-23)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.3.1...wasm-v1.4.0)

### Added

- Add support for `did:jwk` resolution [\#1404](https://github.com/iotaledger/identity/pull/1404)
- Linked Verifiable Presentations [\#1398](https://github.com/iotaledger/identity/pull/1398)

## [wasm-v1.3.1](https://github.com/iotaledger/identity/tree/wasm-v1.3.1) (2024-06-28)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.3.0...wasm-v1.3.1)

### Patch

- Make base64 encoding target independent in `KeyIdMemStore` in wasm bindings [\#1386](https://github.com/iotaledger/identity/pull/1386)

## [wasm-v1.3.0](https://github.com/iotaledger/identity/tree/wasm-v1.3.0) (2024-05-28)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.2.0...wasm-v1.3.0)

### Added

- Add ZK BBS+-based selectively disclosable credentials \(JPT\) [\#1355](https://github.com/iotaledger/identity/pull/1355)

### Patch

- Support for specification-compliant verification method type `JsonWebKey2020` [\#1367](https://github.com/iotaledger/identity/pull/1367)

## [wasm-v1.2.0](https://github.com/iotaledger/identity/tree/wasm-v1.2.0) (2024-03-27)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.1.0...wasm-v1.2.0)

### Added

- Allow arbitrary verification methods [\#1334](https://github.com/iotaledger/identity/pull/1334)
- use latest release of sd-jwt-payload [\#1333](https://github.com/iotaledger/identity/pull/1333)
- Add constructor for `VerificationMethod` in TS [\#1321](https://github.com/iotaledger/identity/pull/1321)
- Allow setting additional controllers for `IotaDocument` [\#1314](https://github.com/iotaledger/identity/pull/1314)

### Patch

- Support %-encoded characters in DID method id [\#1303](https://github.com/iotaledger/identity/pull/1303)

## [wasm-v1.1.0](https://github.com/iotaledger/identity/tree/wasm-v1.1.0) (2024-02-07)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v1.0.0...wasm-v1.1.0)

### Added

- Update `sd-jwt-payload` dependency [\#1296](https://github.com/iotaledger/identity/pull/1296)
- Add support for StatusList2021 [\#1273](https://github.com/iotaledger/identity/pull/1273)
- Support Selective Disclosure SD-JWT [\#1268](https://github.com/iotaledger/identity/pull/1268)

### Patch

- Fix RevocationBitmap2022 encoding bug [\#1292](https://github.com/iotaledger/identity/pull/1292)
- Credentials cannot be unrevoked with StatusList2021 [\#1284](https://github.com/iotaledger/identity/pull/1284)
- Validate domain-linkage URL making sure they only include an origin [\#1267](https://github.com/iotaledger/identity/pull/1267)

## [wasm-v1.0.0](https://github.com/iotaledger/identity/tree/wasm-v1.0.0) (2023-11-02)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v0.6.0...wasm-v1.0.0)

### Changed

- Allow custom `kid` to be set in JWS [\#1239](https://github.com/iotaledger/identity/pull/1239)
- Add dedicated EdDSA verifier crate [\#1238](https://github.com/iotaledger/identity/pull/1238)
- Change `verifiable_credential` to type `Vec<CRED>` in `Presentation` [\#1231](https://github.com/iotaledger/identity/pull/1231)
- Polish Wasm bindings [\#1206](https://github.com/iotaledger/identity/pull/1206)
- Polish `identity_credential` [\#1205](https://github.com/iotaledger/identity/pull/1205)
- Polish `identity_iota_core` [\#1203](https://github.com/iotaledger/identity/pull/1203)
- Upgrade `client-wasm` to `sdk-wasm` [\#1202](https://github.com/iotaledger/identity/pull/1202)
- Rename `JwtPresentation` to `Presentation` [\#1200](https://github.com/iotaledger/identity/pull/1200)
- Remove legacy signing and verification APIs [\#1194](https://github.com/iotaledger/identity/pull/1194)
- Remove old `Presentation` type [\#1190](https://github.com/iotaledger/identity/pull/1190)
- Remove reexported `Resolver` validation APIs [\#1183](https://github.com/iotaledger/identity/pull/1183)
- Use JWT credentials for Domain Linkage [\#1180](https://github.com/iotaledger/identity/pull/1180)
- Remove stronghold nodejs bindings [\#1178](https://github.com/iotaledger/identity/pull/1178)
- JwkStorageDocument & JwtCredential validation [\#1152](https://github.com/iotaledger/identity/pull/1152)
- Add initial PublicKeyJwk support [\#1143](https://github.com/iotaledger/identity/pull/1143)
- Refactor `MethodType` to make it extensible [\#1112](https://github.com/iotaledger/identity/pull/1112)
- Remove generics in `CoreDocument`, `VerificationMethod`, `Service`, `DIDUrl` and `LinkedDomainService` [\#1110](https://github.com/iotaledger/identity/pull/1110)
- Update to `iota-client` 2.0.1-rc.4 and `iota-client-wasm` 0.5.0-alpha.6 [\#1088](https://github.com/iotaledger/identity/pull/1088)
- More identifier checks in `CoreDocument` [\#1067](https://github.com/iotaledger/identity/pull/1067)
- Use Bech32-encoded state controller and governor addresses [\#1044](https://github.com/iotaledger/identity/pull/1044)
- Rename `MixedResolver` to `Resolver` in Wasm [\#1026](https://github.com/iotaledger/identity/pull/1026)
- Expose iteration over verification relationship fields [\#1024](https://github.com/iotaledger/identity/pull/1024)
- Add length prefix to DID Document payloads [\#1010](https://github.com/iotaledger/identity/pull/1010)
- Update Wasm credential, presentation validators for Stardust [\#1004](https://github.com/iotaledger/identity/pull/1004)
- Rename `Stardust` types to `Iota` [\#1000](https://github.com/iotaledger/identity/pull/1000)
- Change Stardust DID method to IOTA [\#982](https://github.com/iotaledger/identity/pull/982)
- Add Wasm Stardust Client [\#975](https://github.com/iotaledger/identity/pull/975)
- Generalized Resolver [\#970](https://github.com/iotaledger/identity/pull/970)
- Change `Storage` to handle `CoreDID` [\#968](https://github.com/iotaledger/identity/pull/968)
- Change `Storage` to store arbitrary blobs [\#953](https://github.com/iotaledger/identity/pull/953)
- Change `Service` `type` field to allow sets [\#944](https://github.com/iotaledger/identity/pull/944)
- Generalise `CredentialValidator`, `PresentationValidator` to support arbitrary DID Documents [\#935](https://github.com/iotaledger/identity/pull/935)

### Added

- Allow arbitrary JWS header parameters [\#1245](https://github.com/iotaledger/identity/pull/1245)
- Allow custom JWT claims for presentations [\#1244](https://github.com/iotaledger/identity/pull/1244)
- Allow custom JWT claims for credentials [\#1237](https://github.com/iotaledger/identity/pull/1237)
- Use `VC Data Model v1.1` JWT encoding instead of `VC-JWT` [\#1234](https://github.com/iotaledger/identity/pull/1234)
- Improve `Proof`  [\#1209](https://github.com/iotaledger/identity/pull/1209)
- Add `resolve_multiple` to Resolver [\#1189](https://github.com/iotaledger/identity/pull/1189)
- Move jwk\_storage and key\_id\_storage to Wasm lib [\#1181](https://github.com/iotaledger/identity/pull/1181)
- Wasm Bindings for JWT Presentations [\#1179](https://github.com/iotaledger/identity/pull/1179)
- Polish JWK thumbprint and document extension API [\#1173](https://github.com/iotaledger/identity/pull/1173)
- Wasm bindings for `KeyIdStorage` [\#1147](https://github.com/iotaledger/identity/pull/1147)
- Introduce `IToCoreDocument` and document locks in the bindings [\#1120](https://github.com/iotaledger/identity/pull/1120)
- Add Wasm Bindings for Domain Linkage [\#1115](https://github.com/iotaledger/identity/pull/1115)
- Add revocation examples [\#1076](https://github.com/iotaledger/identity/pull/1076)
- Add wasm credentials and presentations examples [\#1075](https://github.com/iotaledger/identity/pull/1075)
- Add `IotaDID.fromAliasId` to the Wasm bindings [\#1048](https://github.com/iotaledger/identity/pull/1048)
- Expose Controller and Governor Addresses in metadata [\#1023](https://github.com/iotaledger/identity/pull/1023)
- Add Wasm bindings for `CoreDocument` [\#994](https://github.com/iotaledger/identity/pull/994)
- Add initial Wasm Stardust bindings [\#967](https://github.com/iotaledger/identity/pull/967)

### Patch

- Fix wasm panic caused by a race condition in `IotaDocument` and `CoreDocument` [\#1258](https://github.com/iotaledger/identity/pull/1258)
- Fix issuer claim check in VC [\#1235](https://github.com/iotaledger/identity/pull/1235)
- Update iota.js peer dependency [\#1107](https://github.com/iotaledger/identity/pull/1107)
- Fix unresolved import in TS artifacts [\#1066](https://github.com/iotaledger/identity/pull/1066)
- Fix `IotaDocument.unpackFromOutput` parameter type [\#1041](https://github.com/iotaledger/identity/pull/1041)
- Recommend unique `credentialStatus.id` in `RevocationBitmap2022` [\#1039](https://github.com/iotaledger/identity/pull/1039)
- Support case insensitive serialization of `RentStructure` [\#1012](https://github.com/iotaledger/identity/pull/1012)
- Fix broken wasm bindings compilation [\#995](https://github.com/iotaledger/identity/pull/995)
- Fix DID TypeScript references [\#977](https://github.com/iotaledger/identity/pull/977)

## [wasm-v0.6.0](https://github.com/iotaledger/identity/tree/wasm-v0.6.0) (2022-06-15)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v0.5.0...wasm-v0.6.0)
 
The main feature of this release is the addition of the `RevocationBitmap2022` specification, offering efficient credential revocation on-Tangle. This is the replacement for the `MerkleKeyCollection` removed in v0.5.0, which offered similar functionality but fundamentally failed to scale beyond a few thousand revocations. 

 Other changes include encryption support using Elliptic Curve Diffie-Hellman (ECDH) and quality of life improvements for verifiable credential and presentation types in the Wasm bindings. 

 DID Documents created with v0.5.0 remain compatible with v0.6.0. This will be the last major release prior to changes for the Stardust update. 



### Changed

- Change `remove_service` to return boolean [\#877](https://github.com/iotaledger/identity/pull/877)
- Change `DIDUrl::join` to borrow self [\#871](https://github.com/iotaledger/identity/pull/871)
- Add `RevocationBitmap2022`, bump MSRV to 1.60 [\#861](https://github.com/iotaledger/identity/pull/861)
- Add Wasm `Credential` and `Presentation` field getters and constructors [\#815](https://github.com/iotaledger/identity/pull/815)
- Add Diffie-Hellman key exchange for encryption to `Account` [\#809](https://github.com/iotaledger/identity/pull/809)

### Added

- Implement `ECDH-ES+A256KW` for `Storage` encryption [\#867](https://github.com/iotaledger/identity/pull/867)
- Add Client option for retry publishing behaviour [\#820](https://github.com/iotaledger/identity/pull/820)
- Implement `Storage` test suite [\#791](https://github.com/iotaledger/identity/pull/791)

### Patch

- Fix Wasm `Account.createService` endpoint type [\#819](https://github.com/iotaledger/identity/pull/819)
- Fix omitting `Resolver.verifyPresentation`, `Document.resolveMethod` optional parameters [\#807](https://github.com/iotaledger/identity/pull/807)
- Fix Account `create_signed_*` function return types [\#794](https://github.com/iotaledger/identity/pull/794)
- Fix musl-libc target for Stronghold Node.js bindings [\#789](https://github.com/iotaledger/identity/pull/789)

## [wasm-v0.5.0](https://github.com/iotaledger/identity/tree/wasm-v0.5.0) (2022-03-31)

[Full Changelog](https://github.com/iotaledger/identity/compare/wasm-v0.4.0...wasm-v0.5.0)
 
This release introduces multiple breaking changes to the structure of IOTA DID Documents and their Tangle messages, rendering any identity created with a prior version incompatible and unresolvable. A versioning system has been introduced so any new identities should hopefully be forward compatible with any future breaking changes to the message structure. 

 The main feature of this release is the introduction of WebAssembly (Wasm) bindings for the high-level `Account` API for Javascript/Typescript in both Node.js and the browser. This includes preliminary Stronghold storage bindings but only for Node.js, as it was determined that compiling Stronghold to Wasm for the browser would not be sufficiently secure. Stronghold offers best-effort secure software storage for cryptographic keys, written in Rust. To use the Stronghold storage package install `@iota/identity-stronghold-nodejs` and follow the instructions of the package [README](https://github.com/iotaledger/identity/tree/dev/bindings/stronghold-nodejs). 

 Note that all features related to diff chain updates are now marked as deprecated. Diff chains are a useful optimisation when publishing many updates to a DID Document. However, their design may be incompatible with upcoming changes to the IOTA network and should be considered unstable. 

 Another major change is the removal of the `MerkleKeyCollection` verification method type, which provided a compact representation for issuing and revoking Verifiable Credentials with multiple cryptographic keys. The `MerkleKeyCollection` suffered from disadvantages which limited scalability when managing more than a few thousand keys. While these disadvantages could be mitigated somewhat, the decision was made to replace it with one or more alternatives not affected by its fundamental limitations, upcoming in the next major release.

### Changed

- Add Wasm `Proof`, rename `Signature` structs to `Proof` [\#776](https://github.com/iotaledger/identity/pull/776)
- Replace `MethodSecret` with `MethodContent` enum [\#764](https://github.com/iotaledger/identity/pull/764)
- Change document metadata `created`, `updated` to be optional [\#753](https://github.com/iotaledger/identity/pull/753)
- Refactor Storage Signature [\#738](https://github.com/iotaledger/identity/pull/738)
- Add X25519 key and verification method support [\#735](https://github.com/iotaledger/identity/pull/735)
- Change Wasm key types to `UInt8Array` [\#734](https://github.com/iotaledger/identity/pull/734)
- Refactor `KeyLocation` [\#729](https://github.com/iotaledger/identity/pull/729)
- Move DID Document proof outside metadata [\#728](https://github.com/iotaledger/identity/pull/728)
- Replace Wasm getters and setters with methods [\#706](https://github.com/iotaledger/identity/pull/706)
- Replace Wasm `Config` with `ClientConfig` interface [\#696](https://github.com/iotaledger/identity/pull/696)
- Change `IotaDocument::verify_document` from a static function to a method [\#675](https://github.com/iotaledger/identity/pull/675)
- Make Wasm support dependent on `target_arch` rather than feature [\#666](https://github.com/iotaledger/identity/pull/666)
- Refactor `CoreDocument`, `VerificationMethod`, `Service` to use generic DID [\#655](https://github.com/iotaledger/identity/pull/655)
- Change `also_known_as` type to `OrderedSet` [\#632](https://github.com/iotaledger/identity/pull/632)
- Add union type parameters [\#616](https://github.com/iotaledger/identity/pull/616)
- Fix dependent diff updates being rejected [\#605](https://github.com/iotaledger/identity/pull/605)
- Overhaul `CredentialValidator`, add `PresentationValidator` [\#599](https://github.com/iotaledger/identity/pull/599)
- Remove JSON string escaping in diff messages [\#598](https://github.com/iotaledger/identity/pull/598)
- Replace `ClientMap` with new `Resolver` [\#594](https://github.com/iotaledger/identity/pull/594)
- Rename Wasm `VerifiableCredential`, `VerifiablePresentation`  [\#551](https://github.com/iotaledger/identity/pull/551)
- Add signature `created`, `expires`, `challenge`, `domain`, `purpose` [\#548](https://github.com/iotaledger/identity/pull/548)
- Refactor document metadata [\#540](https://github.com/iotaledger/identity/pull/540)
- Replace `chrono` with `time` [\#529](https://github.com/iotaledger/identity/pull/529)
- Rename `DocumentDiff` to `DiffMessage` [\#511](https://github.com/iotaledger/identity/pull/511)
- Deterministic ordering of competing messages [\#506](https://github.com/iotaledger/identity/pull/506)
- Check for existence & duplication of methods in `CoreDocument` [\#504](https://github.com/iotaledger/identity/pull/504)
- Annotate Wasm async function return types [\#501](https://github.com/iotaledger/identity/pull/501)
- Add `ExplorerUrl` to replace `Network` explorer methods [\#496](https://github.com/iotaledger/identity/pull/496)
- Update `ServiceEndpoint` to support sets and maps [\#485](https://github.com/iotaledger/identity/pull/485)
- Add message compression and versioning [\#466](https://github.com/iotaledger/identity/pull/466)
- Update document signing key constraints and methods [\#458](https://github.com/iotaledger/identity/pull/458)

### Added

- Expose Ed25519, X25519 length constants [\#772](https://github.com/iotaledger/identity/pull/772)
- Add deep clone function in Wasm [\#705](https://github.com/iotaledger/identity/pull/705)
- Add `Duration` for `Timestamp` arithmetic [\#684](https://github.com/iotaledger/identity/pull/684)
- Add `Client` fallback to local PoW option [\#682](https://github.com/iotaledger/identity/pull/682)
- Add Wasm `Service` constructor and field getters [\#680](https://github.com/iotaledger/identity/pull/680)
- Complete `Document` Wasm bindings [\#679](https://github.com/iotaledger/identity/pull/679)
- Add `Document.signDocument` for Wasm [\#674](https://github.com/iotaledger/identity/pull/674)
- Add Wasm bindings for `set_controller` and `set_also_known_as` in the `Account` [\#668](https://github.com/iotaledger/identity/pull/668)
- Add NodeJs bindings for Stronghold `Storage` [\#660](https://github.com/iotaledger/identity/pull/660)
- Add Wasm `Account` `Storage` interface [\#597](https://github.com/iotaledger/identity/pull/597)
- Add Wasm bindings for the `Account` [\#574](https://github.com/iotaledger/identity/pull/574)
- Filter out DiffMessages updating signing methods [\#519](https://github.com/iotaledger/identity/pull/519)
- Add publish with retry method [\#455](https://github.com/iotaledger/identity/pull/455)

### Patch

- Fix stronghold.ts key types [\#763](https://github.com/iotaledger/identity/pull/763)
- Fix `Uint8Array` references [\#760](https://github.com/iotaledger/identity/pull/760)
- Enable Wasm weak references for automatic garbage collection [\#694](https://github.com/iotaledger/identity/pull/694)
- Fix `WasmTimestamp` JSON serialization [\#688](https://github.com/iotaledger/identity/pull/688)
- Fix Wasm `DID` conversion error names [\#651](https://github.com/iotaledger/identity/pull/651)
- Support verification methods with the same fragment [\#623](https://github.com/iotaledger/identity/pull/623)
- Use node-fetch \>= 2.6.7 [\#617](https://github.com/iotaledger/identity/pull/617)
- Fix diff properties \(de\)serialization [\#611](https://github.com/iotaledger/identity/pull/611)
- Fix incorrect names for `ResolvedDocument.integrationMessageId` & `mergeDiff`  [\#600](https://github.com/iotaledger/identity/pull/600)
- Fix node-fetch conflict when multiple versions are included [\#587](https://github.com/iotaledger/identity/pull/587)
- Enable local proof-of-work fallback [\#579](https://github.com/iotaledger/identity/pull/579)
- Fix `Timestamp` in the Wasm bindings [\#541](https://github.com/iotaledger/identity/pull/541)
- Improve client error messages [\#512](https://github.com/iotaledger/identity/pull/512)
- Fix credential validation failing for documents with diff updates [\#490](https://github.com/iotaledger/identity/pull/490)

### Deprecated

- Deprecate diff chain features [\#759](https://github.com/iotaledger/identity/pull/759)

### Removed

- Remove `MerkleKeyCollection` [\#755](https://github.com/iotaledger/identity/pull/755)
- Remove `Storage::set_password` [\#733](https://github.com/iotaledger/identity/pull/733)
- Remove `publicKeyJwk` [\#732](https://github.com/iotaledger/identity/pull/732)

## [wasm-v0.4.0](https://github.com/iotaledger/identity/tree/wasm-v0.4.0) (2021-11-01)

[Full Changelog](https://github.com/iotaledger/identity/compare/360bf5ce64a7f418249cdeadccb22b9aea7daeb6...wasm-v0.4.0)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
