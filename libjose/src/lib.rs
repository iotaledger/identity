// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # libjose
//!
//! A library for JSON Object Signing and Encryption (JOSE).
//!
//! ## References
//! - [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
//! - [JWT Handbook](https://auth0.com/e-books/jwt-handbook)
//!
//! ### RFCs
//! - [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518)
//! - [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//! - [JSON Web Key](https://tools.ietf.org/html/rfc7517)
//! - [JSON Web Key Thumbprint](https://tools.ietf.org/html/rfc7638)
//! - [JSON Web Signature](https://tools.ietf.org/html/rfc7515)
//! - [JSON Web Signature Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
//! - [JSON Web Token](https://tools.ietf.org/html/rfc7519)
//! - [CFRG Elliptic Curve ECDH and Signatures](https://tools.ietf.org/html/rfc8037)
//! - [JOSE Registrations for Web Authentication Algorithms](https://tools.ietf.org/html/rfc8812)
//! - [Chacha derived AEAD algorithms in JOSE](https://tools.ietf.org/html/draft-amringer-jose-chacha-02)
//! - [JSON Web Token Best Current Practices](https://tools.ietf.org/html/rfc8725)
//! - [Public Key Authenticated Encryption for JOSE: ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03)
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::upper_case_acronyms)]

#[cfg(not(feature = "alloc"))]
compile_error!("This crate does not yet support environments without liballoc.");

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate serde;

#[macro_use]
mod macros;

pub mod error;
pub mod jose;
pub mod jwe;
pub mod jwk;
pub mod jwm;
pub mod jws;
pub mod jwt;
#[doc(hidden)]
pub mod utils;

mod lib {
  #[cfg(all(feature = "alloc", not(feature = "std")))]
  pub use alloc::vec;
  #[cfg(feature = "std")]
  pub use std::vec;

  #[cfg(all(feature = "alloc", not(feature = "std")))]
  pub use alloc::borrow::{Cow, ToOwned};
  #[cfg(feature = "std")]
  pub use std::borrow::{Cow, ToOwned};

  #[cfg(all(feature = "alloc", not(feature = "std")))]
  pub use alloc::string::{String, ToString};
  #[cfg(feature = "std")]
  pub use std::string::{String, ToString};

  #[cfg(all(feature = "alloc", not(feature = "std")))]
  pub use alloc::vec::Vec;
  #[cfg(feature = "std")]
  pub use std::vec::Vec;
}
