// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! An implementation of `now_utc` which calls out to an externally defined function.
use crate::common::Timestamp;

/// Register a function to be invoked by `identity_core` in order to get a [Timestamp] representing
/// "now".
///
/// ## Writing a custom `now_utc` implementation
///
/// The function to register must have the same signature as
/// [`Timestamp::now_utc`](Timestamp::now_utc). The function can be defined
/// wherever you want, either in root crate or a dependent crate.
///
/// For example, if we wanted a `static_now_utc` crate containing an
/// implementation that always returns the same timestamp, we would first depend on `identity_core`
/// (for the [`Timestamp`] type) in `static_now_utc/Cargo.toml`:
/// ```toml
/// [dependencies]
/// identity_core = "1"
/// ```
/// Note that the crate containing this function does **not** need to enable the
/// `"custom_time"` Cargo feature.
///
/// Next, in `static_now_utc/src/lib.rs`, we define our function:
/// ```rust
/// use identity_core::common::Timestamp;
///
/// // Some fixed timestamp
/// const MY_FIXED_TIMESTAMP: i64 = 1724402964;
/// pub fn static_now_utc() -> Timestamp {
///   Timestamp::from_unix(MY_FIXED_TIMESTAMP).unwrap()
/// }
/// ```
///
/// ## Registering a custom `now_utc` implementation
///
/// Functions can only be registered in the root binary crate. Attempting to
/// register a function in a non-root crate will result in a linker error.
/// This is similar to
/// [`#[panic_handler]`](https://doc.rust-lang.org/nomicon/panic-handler.html) or
/// [`#[global_allocator]`](https://doc.rust-lang.org/edition-guide/rust-2018/platform-and-target-support/global-allocators.html),
/// where helper crates define handlers/allocators but only the binary crate
/// actually _uses_ the functionality.
///
/// To register the function, we first depend on `static_now_utc` _and_
/// `identity_core` in `Cargo.toml`:
/// ```toml
/// [dependencies]
/// static_now_utc = "0.1"
/// identity_core = { version = "1", features = ["custom_time"] }
/// ```
///
/// Then, we register the function in `src/main.rs`:
/// ```rust
/// # mod static_now_utc { pub fn static_now_utc() -> Timestamp { unimplemented!() } }
///
/// use identity_core::register_custom_now_utc;
/// use static_now_utc::static_now_utc;
///
/// register_custom_now_utc!(static_now_utc);
/// ```
///
/// Now any user of `now_utc` (direct or indirect) on this target will use the
/// registered function.
#[macro_export]
macro_rules! register_custom_now_utc {
  ($path:path) => {
    const __GET_TIME_INTERNAL: () = {
      // We use Rust ABI to be safe against potential panics in the passed function.
      #[no_mangle]
      unsafe fn __now_utc_custom() -> Timestamp {
        // Make sure the passed function has the type of `now_utc_custom`
        type F = fn() -> Timestamp;
        let f: F = $path;
        f()
      }
    };
  };
}

pub(crate) fn now_utc_custom() -> Timestamp {
  extern "Rust" {
    fn __now_utc_custom() -> Timestamp;
  }
  unsafe { __now_utc_custom() }
}
