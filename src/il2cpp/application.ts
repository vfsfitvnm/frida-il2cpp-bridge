namespace Il2Cpp {
    export const application = {
        /** */
        get dataPath(): string {
            const get_persistentDataPath = Il2Cpp.Runtime.internalCall("UnityEngine.Application::get_persistentDataPath", "pointer", [])!;
            return new Il2Cpp.String(get_persistentDataPath()).content!;
        },

        /** */
        get identifier(): string | null {
            const get_identifier =
                Il2Cpp.Runtime.internalCall("UnityEngine.Application::get_identifier", "pointer", []) ??
                Il2Cpp.Runtime.internalCall("UnityEngine.Application::get_bundleIdentifier", "pointer", []);

            return get_identifier ? new Il2Cpp.String(get_identifier()).content : null;
        },

        /** Gets the version of the application */
        get version(): string | null {
            const get_version = Il2Cpp.Runtime.internalCall("UnityEngine.Application::get_version", "pointer", []);
            return get_version ? new Il2Cpp.String(get_version()).content : null;
        }
    };

    /** Gets the Unity version of the current application. */
    export declare const unityVersion: string;
    // prettier-ignore
    getter(Il2Cpp, "unityVersion", () => {
        const get_unityVersion = Il2Cpp.Runtime.internalCall("UnityEngine.Application::get_unityVersion", "pointer", []);

        if (get_unityVersion != null) {
            return new Il2Cpp.String(get_unityVersion()).content!;
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
}
