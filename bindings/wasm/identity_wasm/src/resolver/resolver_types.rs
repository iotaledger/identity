// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Promise<Array<CoreDocument | IToCoreDocument>>")]
  pub type PromiseArrayIToCoreDocument;

  #[wasm_bindgen(typescript_type = "Promise<CoreDocument | IToCoreDocument>")]
  pub type PromiseIToCoreDocument;

  #[wasm_bindgen(typescript_type = "CoreDocument | IToCoreDocument | undefined")]
  pub type OptionIToCoreDocument;

  #[wasm_bindgen(typescript_type = "Array<CoreDocument | IToCoreDocument> | undefined")]
  pub type OptionArrayIToCoreDocument;
}
