import { defineConfig } from "vite";

export default defineConfig(({ command, mode }) => {
    // variables will be set during build time
    const EXPOSED_ENVS = [
        "IOTA_IDENTITY_PKG_ID",
        "NETWORK_NAME_FAUCET",
        "NETWORK_URL",
    ];

    return {
        define: EXPOSED_ENVS.reduce((prev, env_var) => {
            const var_value = globalThis?.process?.env?.[env_var];
            if (var_value) {
                console.log("exposing", env_var, var_value);
                prev[`process.env.${env_var}`] = JSON.stringify(var_value);
            }
            return prev;
        }, {}),
        server: {
            // open on default port or fail to make CI consistent
            strictPort: true,
        },
        build: {
            rollupOptions: {
                output: {
                    interop: "auto",
                },
            },
        },
        // // resolve: {
        // //     alias: [{ find: "@digitalcredentials/did-method-key", replacement: "@digitalcredentials/did-method-key/esm/dist/" }],
        // // },
        // optimizeDeps: {
        //     exclude: ["@digitalcredentials/did-method-key"]
        // }
    };
});
