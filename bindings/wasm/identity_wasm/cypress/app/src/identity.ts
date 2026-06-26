import url from "@iota/identity-wasm/web/identity_wasm_bg.wasm?url";

import { init } from "@iota/identity-wasm/web";
import { main } from "../../../examples/dist/web/web-main";

export const runTest = async (example: string) => {
    try {
        await main(example);
        console.log("success");
    } catch (error) {
        throw (error);
    }
};

init(url)
    .then(() => {
        console.log("init");
    });
