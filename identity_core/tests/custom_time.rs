// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Timestamp;
use identity_core::register_custom_now_utc;

const STATIC_TIME: i64 = 1724402964; // 2024-08-23T11:33:30+00:00
pub fn static_now_utc() -> Timestamp {
  Timestamp::from_unix(STATIC_TIME).unwrap()
}

register_custom_now_utc!(static_now_utc);

#[test]
fn should_use_registered_static_time() {
  let timestamp = Timestamp::now_utc();
  assert_eq!(timestamp.to_unix(), STATIC_TIME)
}
