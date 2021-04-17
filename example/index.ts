import { Il2Cpp } from "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    // Uncomment for REPL access
    // (global as any).Il2Cpp = Il2Cpp;
}

main().catch(error => console.log(error.stack));
