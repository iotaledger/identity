// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

import { createIdentity } from "./0_basic/0_create_did";
import { updateIdentity } from "./0_basic/1_update_did";
import { resolveIdentity } from "./0_basic/2_resolve_did";
import { deactivateIdentity } from "./0_basic/3_deactivate_did";
import { deleteIdentity } from "./0_basic/4_delete_did";
import { createVC } from "./0_basic/5_create_vc";
import { createVP } from "./0_basic/6_create_vp";
import { revokeVC } from "./0_basic/7_revoke_vc";
import { didControlsDid } from "./1_advanced/0_did_controls_did";
import { sdJwtVc } from "./1_advanced/10_sd_jwt_vc";
import { pq } from "./1_advanced/pq";
import { hybrid } from "./1_advanced/hybrid";
import { didIssuesNft } from "./1_advanced/1_did_issues_nft";
import { nftOwnsDid } from "./1_advanced/2_nft_owns_did";
import { didIssuesTokens } from "./1_advanced/3_did_issues_tokens";
import { customResolution } from "./1_advanced/4_custom_resolution";
import { domainLinkage } from "./1_advanced/5_domain_linkage";
import { sdJwt } from "./1_advanced/6_sd_jwt";
import { statusList2021 } from "./1_advanced/7_status_list_2021";
import { zkp } from "./1_advanced/8_zkp";
import { zkp_revocation } from "./1_advanced/9_zkp_revocation";

async function main() {
    // Extract example name.
    if (process.argv.length != 3) {
        throw "Please specify an example name, e.g. '0_create_did'";
    }
    const argument = process.argv[2].toLowerCase();

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
            return await deleteIdentity();
        case "5_create_vc":
            return await createVC();
        case "6_create_vp":
            return await createVP();
        case "7_revoke_vc":
            return await revokeVC();
        case "0_did_controls_did":
            return await didControlsDid();
        case "1_did_issues_nft":
            return await didIssuesNft();
        case "2_nft_owns_did":
            return await nftOwnsDid();
        case "3_did_issues_tokens":
            return await didIssuesTokens();
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
        case "pq":
            return await pq();
        case "hybrid":
            return await hybrid();
        default:
            throw "Unknown example name: '" + argument + "'";
    }
}

main()
    .catch((error) => {
        console.log("Example error:", error);
    });
