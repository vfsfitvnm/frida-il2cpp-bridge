import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    console.log(`Hello, Unity ${Il2Cpp.unityVersion}`);
});
