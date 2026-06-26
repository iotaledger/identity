// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Additional functionality for DID assisted digital signatures.

pub use self::jwp_verification_options::JwpVerificationOptions;
pub use self::jws_verification_options::JwsVerificationOptions;

mod jwp_verification_options;
mod jws_verification_options;
