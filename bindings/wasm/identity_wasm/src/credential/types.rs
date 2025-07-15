// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Array<string | Record<string, any>>")]
  pub type ArrayContext;

  #[wasm_bindgen(typescript_type = "Array<Evidence>")]
  pub type ArrayEvidence;

  #[wasm_bindgen(typescript_type = "string | Issuer")]
  pub type UrlOrIssuer;

  #[wasm_bindgen(typescript_type = "Array<Policy>")]
  pub type ArrayPolicy;

  #[wasm_bindgen(typescript_type = "Array<RefreshService>")]
  pub type ArrayRefreshService;

  #[wasm_bindgen(typescript_type = "Array<Schema>")]
  pub type ArraySchema;

  #[wasm_bindgen(typescript_type = "Array<Status>")]
  pub type ArrayStatus;

  #[wasm_bindgen(typescript_type = "Array<Subject>")]
  pub type ArraySubject;

  #[wasm_bindgen(typescript_type = "Array<Credential>")]
  pub type ArrayCredential;

  #[wasm_bindgen(typescript_type = "Array<DecodedJwtCredential>")]
  pub type ArrayDecodedJwtCredential;

  #[wasm_bindgen(typescript_type = "Array<Jwt>")]
  pub type ArrayJwt;

  #[wasm_bindgen(typescript_type = "Array<UnknownCredential>")]
  pub type ArrayUnknownCredential;

  #[wasm_bindgen(typescript_type = "Array<CoreDID>")]
  pub type ArrayCoreDID;

  #[wasm_bindgen(typescript_type = "Status")]
  pub type WasmStatus;
}

#[wasm_bindgen(typescript_custom_section)]
const I_EVIDENCE: &'static str = r#"
/** Information used to increase confidence in the claims of a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#evidence) */
interface Evidence {
  /** A URL that allows retrieval of information about the evidence. */
  readonly id?: string;
  /** The type(s) of the credential evidence. */
  readonly type: string | Array<string>;
  /** Additional properties of the credential evidence. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_ISSUER: &'static str = r#"
/** An identifier representing the issuer of a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#issuer) */
interface Issuer {
  /** A URL identifying the credential issuer. */
  readonly id: string;
  /** Additional properties of the credential issuer. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_POLICY: &'static str = r#"
/** Information used to express obligations, prohibitions, and permissions about a {@link Credential} or {@link Presentation}.

[More Info](https://www.w3.org/TR/vc-data-model/#terms-of-use) */
interface Policy {
  /** A URL identifying the credential terms-of-use. */
  readonly id?: string;
  /** The type(s) of the credential terms-of-use. */
  readonly type: string | Array<string>;
  /** Additional properties of the credential terms-of-use. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_REFRESH_SERVICE: &'static str = r#"
/** Information used to refresh or assert the status of a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#refreshing) */
interface RefreshService {
  /** The URL of the credential refresh service. */
  readonly id: string;
  /** The type(s) of the credential refresh service. */
  readonly type: string | Array<string>;
  /** Additional properties of the credential refresh service. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_SCHEMA: &'static str = r#"
/** Information used to validate the structure of a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#data-schemas) */
interface Schema {
  /** A URL identifying the credential schema file. */
  readonly id: string;
  /** The type(s) of the credential schema. */
  readonly type: string | Array<string>;
  /** Additional properties of the credential schema. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_STATUS: &'static str = r#"
/** Information used to determine the current status of a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#status) */
interface Status {
  /** A URL identifying the credential status. */
  readonly id: string;
  /** The type of the credential status. */
  readonly type: string;
  /** Additional properties of the credential status. */
  readonly [properties: string]: unknown;
}"#;

#[wasm_bindgen(typescript_custom_section)]
const I_SUBJECT: &'static str = r#"
/** An entity who is the target of a set of claims in a {@link Credential}.

[More Info](https://www.w3.org/TR/vc-data-model/#credential-subject) */
interface Subject {
  /** A URI identifying the credential subject. */
  readonly id?: string | CoreDID | IotaDID;
  /** Additional properties of the credential subject. */
  readonly [properties: string]: unknown;
}"#;
