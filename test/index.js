import { test } from "node:test";
import { strict as assert } from "node:assert";
import { promises as fs } from "node:fs";
import { clearInterval } from "node:timers";
const frida = await import("frida");

const unityVersions = ["5.3.5f1", "2018.3.0f1", "2019.3.0f1", "2021.2.0f1"];
const src = (await fs.readFile("../dist/index.js", "utf-8")) + (await fs.readFile("./test.js", "utf-8"));

for (const unityVersion of unityVersions) {
    const host = await frida.spawn(["host", `./${unityVersion}/.build/out`]);
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
