// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Number<N> {
  Num(N),
  Str(String),
}

macro_rules! impl_conversions {
  ($t:ty) => {
    impl TryFrom<Number<$t>> for $t {
      type Error = <$t as FromStr>::Err;
      fn try_from(value: Number<$t>) -> Result<$t, Self::Error> {
        match value {
          Number::Num(n) => Ok(n),
          Number::Str(s) => s.parse(),
        }
      }
    }

    impl From<$t> for Number<$t> {
      fn from(value: $t) -> Number<$t> {
        Number::Num(value)
      }
    }
  };
}

impl_conversions!(u8);
impl_conversions!(u16);
impl_conversions!(u32);
impl_conversions!(u64);
impl_conversions!(u128);
impl_conversions!(usize);

impl_conversions!(i8);
impl_conversions!(i16);
impl_conversions!(i32);
impl_conversions!(i64);
impl_conversions!(i128);
impl_conversions!(isize);
