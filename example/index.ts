import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    // code here
}

main().catch(error => console.log(error.stack));
