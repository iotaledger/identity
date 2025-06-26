// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::error::Error;
use std::fmt::Debug;
use std::fmt::Display;

#[cfg(target_arch = "wasm32")]
use product_common::bindings::wasm_error;

/// A container implementing the [`std::error::Error`] trait.
///
/// Instances always carry a corresponding `kind` of type `T` and may be extended with a custom error
/// message and source.
///
/// This type is mainly designed to accommodate for the [single struct error design pattern](https://nrc.github.io/error-docs/error-design/error-type-design.html#single-struct-style).
///
/// When used in a specialized context it is recommended to use a type alias (i.e. `type MyError =
/// SingleStructError<MyErrorKind>`).
#[derive(Debug)]
pub struct SingleStructError<T: Debug + Display> {
  repr: Repr<T>,
}

#[cfg(target_arch = "wasm32")]
impl<T: Debug + Display> From<SingleStructError<T>> for wasm_error::WasmError<'_> {
  fn from(error: SingleStructError<T>) -> Self {
    Self {
      name: Cow::Borrowed(std::any::type_name::<SingleStructError<T>>()),
      message: Cow::Owned(wasm_error::ErrorMessage(&error).to_string()),
    }
  }
}

impl<T: Display + Debug> Display for SingleStructError<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.repr {
      Repr::Simple(ref kind) => write!(f, "{kind}"),
      Repr::Extensive(ref extensive) => {
        write!(f, "{}", &extensive.kind)?;
        let Some(ref message) = extensive.message else {
          return Ok(());
        };
        write!(f, " message: {}", message.as_ref())
      }
    }
  }
}

impl<T: Debug + Display> Error for SingleStructError<T> {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    self.extensive().and_then(|err| {
      err
        .source
        .as_ref()
        .map(|source| source.as_ref() as &(dyn Error + 'static))
    })
  }
}

#[derive(Debug)]
struct Extensive<T: Debug + Display> {
  kind: T,
  source: Option<Box<dyn Error + Send + Sync + 'static>>,
  message: Option<Cow<'static, str>>,
}

#[derive(Debug)]
enum Repr<T: Debug + Display> {
  Simple(T),
  Extensive(Box<Extensive<T>>),
}

impl<T: Debug + Display> From<T> for SingleStructError<T> {
  fn from(kind: T) -> Self {
    Self::new(kind)
  }
}

impl<T: Debug + Display> From<Box<Extensive<T>>> for SingleStructError<T> {
  fn from(extensive: Box<Extensive<T>>) -> Self {
    Self {
      repr: Repr::Extensive(extensive),
    }
  }
}

impl<T: Debug + Display> SingleStructError<T> {
  /// Constructs a new [`SingleStructError`].  
  pub fn new(kind: T) -> Self {
    Self {
      repr: Repr::Simple(kind),
    }
  }

  /// Returns a reference to the corresponding `kind` of this error.
  pub fn kind(&self) -> &T {
    match self.repr {
      Repr::Simple(ref cause) => cause,
      Repr::Extensive(ref extensive) => &extensive.kind,
    }
  }

  /// Converts this error into the corresponding `kind` of this error.
  pub fn into_kind(self) -> T {
    match self.repr {
      Repr::Simple(cause) => cause,
      Repr::Extensive(extensive) => extensive.kind,
    }
  }

  /// Returns a reference to the custom message of the [`SingleStructError`] if it was set.
  pub fn custom_message(&self) -> Option<&str> {
    self
      .extensive()
      .into_iter()
      .flat_map(|extensive| extensive.message.as_deref())
      .next()
  }

  /// Returns a reference to the attached source of the [`SingleStructError`] if it was set.
  pub fn source_ref(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
    self.extensive().and_then(|extensive| extensive.source.as_deref())
  }

  /// Converts this error into the source error if it was set.
  pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync + 'static>> {
    self.into_extensive().source
  }

  fn extensive(&self) -> Option<&Extensive<T>> {
    match self.repr {
      Repr::Extensive(ref extensive) => Some(extensive.as_ref()),
      _ => None,
    }
  }

  fn into_extensive(self) -> Box<Extensive<T>> {
    match self.repr {
      Repr::Extensive(extensive) => extensive,
      Repr::Simple(kind) => Box::new(Extensive {
        kind,
        source: None,
        message: None,
      }),
    }
  }

  /// Updates the `source` of the [`SingleStructError`].
  pub fn with_source(self, source: impl Into<Box<dyn Error + Send + Sync + 'static>>) -> Self {
    self._with_source(source.into())
  }

  fn _with_source(self, source: Box<dyn Error + Send + Sync + 'static>) -> Self {
    let mut extensive = self.into_extensive();
    extensive.as_mut().source = Some(source);
    Self::from(extensive)
  }

  /// Updates the custom message of the [`SingleStructError`].
  pub fn with_custom_message(self, message: impl Into<Cow<'static, str>>) -> Self {
    self._with_custom_message(message.into())
  }

  fn _with_custom_message(self, message: Cow<'static, str>) -> Self {
    let mut extensive = self.into_extensive();
    extensive.as_mut().message = Some(message);
    Self::from(extensive)
  }
}
