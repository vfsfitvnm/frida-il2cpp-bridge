import { promises as fs } from "fs";
import path from "path";
import frida from "frida";

const root = path.join(path.dirname(import.meta.url.replace(/^file:\/\//, "")), "..");

const src = await fs.readFile(path.join(root, "test", "agent", "dist", "index.js"), "utf-8");

const unityVersions = await fs.readdir(path.join(root, "build"));

const summary = { passed: 0, failed: 0 };

for (const unityVersion of unityVersions) {
    const buildPath = path.join(root, "build", unityVersion);

    if (!(await fs.lstat(buildPath)).isDirectory()) continue;

    const host = await frida.spawn([path.join(root, "build", "host"), path.join(buildPath, "out")]);
    const session = await frida.attach(host);

    const script = await session.createScript(src, { name: "index" });
    script.message.connect(message => {
        switch (message.type) {
            case frida.MessageType.Error: {
                console.error(message);
                break;
            }
        }
    });

    await script.load();
    await frida.resume(host);

    const testNames = await script.exports.$init(path.join(root, "test", "agent", "dist", "index.js.map"), unityVersion);

    console.log(`\x1b[94m\x1b[1m►\x1b[22m\x1b[0m ${unityVersion} \x1b[2m${testNames.length} tests\x1b[0m`);

    const failures = [];
    for (const name of testNames) {
        const time = +new Date();
        try {
            await script.exports[name]();
        } catch (err) {
            summary.failed++;
            failures.push({ name, err });
            continue;
        }
        const duration = +new Date() - time;
        summary.passed++;
        console.log(`  \x1b[32m\x1b[1m✓\x1b[22m ${name}\x1b[0m \x1b[2m${duration}ms\x1b[0m`);
    }
    failures.forEach(({ name, err }) => console.log(`  \x1b[31m\x1b[1m𐄂\x1b[22m ${name}:\x1b[0m \x1b[31m${err.stack.replace(/^Error: /, "")}\x1b[0m`));

    await script.unload();
    await frida.kill(host);
}

if (summary.failed > 0) {
    console.log(`\x1b[31m\x1b[1m𐄂\x1b[22m ${summary.failed} test(s) failed\x1b[0m`);
    process.exit(1);
} else {
    console.log(`\x1b[94m\x1b[1m✓\x1b[22m ${summary.passed} test(s) passed\x1b[0m`);
}
