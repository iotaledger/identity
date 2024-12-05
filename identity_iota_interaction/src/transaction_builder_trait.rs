// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ProgrammableTransactionBcs;
use crate::error::Error;

pub trait TransactionBuilderT: Default {
    fn finish(self) -> Result<ProgrammableTransactionBcs, Error>;
}