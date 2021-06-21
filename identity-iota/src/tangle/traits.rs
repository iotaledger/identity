// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::did::IotaDID;
use crate::did::IotaDocument;
use crate::error::Result;
use crate::tangle::MessageId;

pub trait TangleRef {
  fn message_id(&self) -> &MessageId;

  fn set_message_id(&mut self, message_id: MessageId);

  fn previous_message_id(&self) -> &MessageId;

  fn set_previous_message_id(&mut self, message_id: MessageId);
}

#[async_trait::async_trait(?Send)]
pub trait TangleResolve {
  async fn resolve(&self, did: &IotaDID) -> Result<IotaDocument>;
}
