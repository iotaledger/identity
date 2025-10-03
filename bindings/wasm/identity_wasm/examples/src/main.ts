// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { createIdentity } from "./0_basic/0_create_did";
import { updateIdentity } from "./0_basic/1_update_did";
import { resolveIdentity } from "./0_basic/2_resolve_did";
import { deactivateIdentity } from "./0_basic/3_deactivate_did";
import { deleteIdentityDID } from "./0_basic/4_delete_did";
import { createVC } from "./0_basic/5_create_vc";
import { createVP } from "./0_basic/6_create_vp";
import { revokeVC } from "./0_basic/7_revoke_vc";
import { didOwnsDid } from "./1_advanced/0_did_owns_did";
import { sdJwtVc } from "./1_advanced/10_sd_jwt_vc";
import { advancedTransaction } from "./1_advanced/11_advanced_transactions";
import { iotaKeytoolIntegration } from "./1_advanced/12_iota_keytool_integration";
import { linkedVp } from "./1_advanced/13_linked_verifiable_presentation";
import { customResolution } from "./1_advanced/4_custom_resolution";
import { domainLinkage } from "./1_advanced/5_domain_linkage";
import { sdJwt } from "./1_advanced/6_sd_jwt";
import { statusList2021 } from "./1_advanced/7_status_list_2021";
import { zkp } from "./1_advanced/8_zkp";
import { zkp_revocation } from "./1_advanced/9_zkp_revocation";

export async function main(example?: string) {
    // Extract example name.
    const argument = example ?? process.argv?.[2]?.toLowerCase();
    if (!argument) {
        throw "Please specify an example name, e.g. '0_create_did'";
    }

    switch (argument) {
        case "0_create_did":
            return await createIdentity();
        case "1_update_did":
            return await updateIdentity();
        case "2_resolve_did":
            return await resolveIdentity();
        case "3_deactivate_did":
            return await deactivateIdentity();
        case "4_delete_did":
            return await deleteIdentityDID();
        case "5_create_vc":
            return await createVC();
        case "6_create_vp":
            return await createVP();
        case "7_revoke_vc":
            return await revokeVC();
        case "0_did_owns_did":
            return await didOwnsDid();
        case "4_custom_resolution":
            return await customResolution();
        case "5_domain_linkage":
            return await domainLinkage();
        case "6_sd_jwt":
            return await sdJwt();
        case "7_status_list_2021":
            return await statusList2021();
        case "8_zkp":
            return await zkp();
        case "9_zkp_revocation":
            return await zkp_revocation();
        case "10_sd_jwt_vc":
            return await sdJwtVc();
        case "11_advanced_transactions":
            return await advancedTransaction();
        case "12_iota_keytool_integration":
            return await iotaKeytoolIntegration();
        case "13_linked_verifiable_presentation":
            return await linkedVp();
        default:
            throw "Unknown example name: '" + argument + "'";
    }
}

main()
    .catch((error) => {
        console.log("Example error:", error);
    });
