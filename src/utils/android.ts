/** @internal */
namespace Android {
    export declare const apiLevel: number | null;
    // prettier-ignore
    getter(Android, "apiLevel", () => {
        const value = getProperty("ro.build.version.sdk");
        return value ? parseInt(value) : null;
    }, lazy);

    function getProperty(name: string): string | undefined {
        const handle = Module.findExportByName("libc.so", "__system_property_get");

        if (handle) {
            const __system_property_get = new NativeFunction(handle, "void", ["pointer", "pointer"]);

            const value = Memory.alloc(92).writePointer(NULL);
            __system_property_get(Memory.allocUtf8String(name), value);

            return value.readCString() ?? undefined;
        }
    }
}
