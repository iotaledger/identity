const { _ } = Cypress;

describe(
    "Test Examples",
    () => {
        const examples = [
            "0_create_did",
            "1_update_did",
            "2_resolve_did",
            "3_deactivate_did",
            "4_delete_did",
            "5_create_vc",
            "6_create_vp",
            "7_revoke_vc",
            "4_custom_resolution",
            "5_domain_linkage",
            "6_sd_jwt",
            "7_status_list_2021",
            "8_zkp",
            "9_zkp_revocation",
            "10_sd_jwt_vc",
        ];

        _.each(examples, (example) => {
            it(example, () => {
                cy.visit("/", {
                    onBeforeLoad(win) {
                        cy.stub(win.console, "log").as("consoleLog");
                    },
                });
                cy.get("@consoleLog").should("be.calledWith", "init");
                cy.window().then(win => win.runTest(example));
                cy.get("@consoleLog").should("be.calledWith", "success");
            });
        });
    },
);
