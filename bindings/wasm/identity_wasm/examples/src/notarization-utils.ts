// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { TransactionSigner } from "@iota/iota-interaction-ts/node/iota_interaction_ts";
import { IotaClient } from "@iota/iota-sdk/client";
import { NotarizationClient, NotarizationClientReadOnly } from "@iota/notarization/node";
import { NETWORK_URL } from "./util";

export const IOTA_NOTARIZATION_PKG_ID = globalThis?.process?.env?.IOTA_NOTARIZATION_PKG_ID || "";

export async function getNotarizationClient(signer: TransactionSigner): Promise<NotarizationClient> {
    if (!IOTA_NOTARIZATION_PKG_ID) {
        throw new Error(`IOTA_NOTARIZATION_PKG_ID env variable must be provided to run the notarization examples`);
    }

    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const notarizationClientReadOnly = await NotarizationClientReadOnly.createWithPkgId(
        iotaClient,
        IOTA_NOTARIZATION_PKG_ID,
    );

    return await NotarizationClient.create(notarizationClientReadOnly, signer);
}
