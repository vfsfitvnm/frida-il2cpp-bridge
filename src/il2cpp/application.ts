namespace Il2Cpp {
    export const application = {
        /** */
        get dataPath(): string | null {
            return unityEngineCall("get_persistentDataPath");
        },

        /** */
        get identifier(): string | null {
            return unityEngineCall("get_identifier") ?? unityEngineCall("get_bundleIdentifier");
        },

        /** Gets the version of the application */
        get version(): string | null {
            return unityEngineCall("get_version");
        }
    };

    /** Gets the Unity version of the current application. */
    export declare const unityVersion: string;
    // prettier-ignore
    getter(Il2Cpp, "unityVersion", () => {
        const unityVersion = unityEngineCall("get_unityVersion");

        if (unityVersion != null) {
            return unityVersion;
        }

        const searchPattern = "45 64 69 74 6f 72 ?? 44 61 74 61 ?? 69 6c 32 63 70 70";

        for (const range of module.enumerateRanges("r--").concat(Process.getRangeByAddress(module.base))) {
            for (let { address } of Memory.scanSync(range.base, range.size, searchPattern)) {
                while (address.readU8() != 0) {
                    address = address.sub(1);
                }
                const match = UnityVersion.find(address.add(1).readCString());

                if (match != undefined) {
                    return match;
                }
            }
        }

        raise("couldn't determine the Unity version, please specify it manually");
    }, lazy);

    /** @internal */
    export declare const unityVersionIsBelow201830: boolean;
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow201830", () => {
        return UnityVersion.lt(unityVersion, "2018.3.0");
    }, lazy);

    /** @internal */
    export declare const unityVersionIsBelow202120: boolean;
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow202120", () => {
        return UnityVersion.lt(unityVersion, "2021.2.0");
    }, lazy);

    function unityEngineCall(method: string): string | null {
        const handle = Il2Cpp.api.resolveInternalCall(Memory.allocUtf8String("UnityEngine.Application::" + method));
        const nativeFunction = new NativeFunction(handle, "pointer", []);

        return nativeFunction.isNull() ? null : new Il2Cpp.String(nativeFunction()).asNullable()?.content ?? null;
    }
}
