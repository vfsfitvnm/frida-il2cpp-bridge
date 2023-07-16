import { test } from "node:test";
import { strict as assert } from "node:assert";
import { promises as fs } from "node:fs";
import path from "node:path";
import { clearInterval } from "node:timers";
const frida = await import("frida");

const __dirname = path.dirname(import.meta.url).replace(/^file:\/\//, "");

const src = (await fs.readFile(`${__dirname}/../dist/index.js`, "utf-8")) + (await fs.readFile(`${__dirname}/test.js`, "utf-8"));

for (const unityVersion of process.env["UNITY_VERSIONS"].split(" ")) {
    const host = await frida.spawn([`${__dirname}/host`, `${__dirname}/${unityVersion}/.build/out`]);
    const session = await frida.attach(host);

    const script = await session.createScript(`${src}\nconst $EXPECTED_UNITY_VERSION = "${unityVersion}";`);
    await script.load();

    let queue = [];
    script.message.connect(_ => queue.push(_));

    const tests = test(unityVersion, async tester => {
        await new Promise(resolve => {
            const i = setInterval(async () => {
                const messages = queue;
                queue = [];

                for (const message of messages) {
                    if (message["payload"] == "done") {
                        clearInterval(i);
                        resolve();
                        return;
                    }

                    const { title, actual, expected, duration, error } = message["payload"];

                    await tester.test(title, async () => {
                        if (error) {
                            throw error;
                        }
                        // No comment
                        await new Promise(resolve => setTimeout(resolve, duration));
                        assert.strictEqual(actual, expected);
                    });
                }
            }, 20);
        });
    });

    await frida.resume(host);
    await tests;
    await script.unload();
    await frida.kill(host);
}
