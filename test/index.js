import { promises as fs } from "node:fs";
import path from "node:path";
const frida = await import("frida");

const root = path.join(path.dirname(import.meta.url.replace(/^file:\/\//, "")), "..");

const src = (await fs.readFile(path.join(root, "dist", "index.js"), "utf-8")) + "\n" + (await fs.readFile(path.join(root, "test", "agent.js"), "utf-8"));

const unityVersions = await fs.readdir(path.join(root, "build"));

const summary = { passed: 0, failed: 0, failedPayloads: [] };

for (const unityVersion of unityVersions) {
    const buildPath = path.join(root, "build", unityVersion);

    if (!(await fs.lstat(buildPath)).isDirectory()) continue;

    const host = await frida.spawn([path.join(root, "build", "host"), path.join(buildPath, "out")]);
    const session = await frida.attach(host);

    const script = await session.createScript(`${src}\nconst $EXPECTED_UNITY_VERSION = "${unityVersion}";`);
    await script.load();

    const tests = new Promise((resolve, reject) => {
        script.message.connect(message => {
            switch (message.type) {
                case frida.MessageType.Send: {
                    if (message.payload?.type == "summary") {
                        for (const failure of message.payload.failures) {
                            console.log(failure);
                        }
                        console.log();
                        summary.passed += message.payload.passed;
                        summary.failed += message.payload.failed;
                        resolve();
                        return;
                    }

                    console.log(message.payload);
                    break;
                }
                case frida.MessageType.Error: {
                    console.log(message);
                    reject(message);
                    break;
                }
            }
        });
    });

    await frida.resume(host);
    await tests;
    await script.unload();
    await frida.kill(host);
}

if (summary.failed > 0) {
    console.log(`\x1b[31m\x1b[1m𐄂\x1b[22m ${summary.failed} tests failed`);
    process.exit(1);
} else {
    console.log(`\x1b[94m\x1b[1m✓\x1b[22m ${summary.passed} tests passed\x1b[0m`);
}
