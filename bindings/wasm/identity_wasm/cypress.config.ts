import { defineConfig } from "cypress";

export default defineConfig({
    screenshotOnRunFailure: false,
    video: false,
    requestTimeout: 10000,
    defaultCommandTimeout: 60000,
    retries: {
        runMode: 3,
    },
    e2e: {
        baseUrl: "http://localhost:5173",
        supportFile: false,
        setupNodeEvents(on, config) {
            on("before:browser:launch", (browser, launchOptions) => {
                if (browser.family === "firefox") {
                    // Fix to make subtle crypto work in cypress firefox
                    // https://github.com/cypress-io/cypress/issues/18217
                    launchOptions.preferences[
                        "network.proxy.testing_localhost_is_secure_when_hijacked"
                    ] = true;
                    // Temporary fix to allow cypress to control Firefox via CDP
                    // https://github.com/cypress-io/cypress/issues/29713
                    // https://fxdx.dev/deprecating-cdp-support-in-firefox-embracing-the-future-with-webdriver-bidi/
                    launchOptions.preferences[
                        "remote.active-protocols"
                    ] = 3;
                }
                return launchOptions;
            });
        },
    },
});
