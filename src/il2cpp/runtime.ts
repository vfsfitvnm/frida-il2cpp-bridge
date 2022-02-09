import { cache } from "decorator-cache-getter";

/** */
class Il2CppRuntime {
    protected constructor() {}

    /** Gets the allocation granularity. */
    static get allocationGranularity(): number {
        return this.information[5];
    }

    /** Gets the size of the Il2CppArray struct. */
    static get arrayHeaderSize(): number {
        return this.information[2];
    }

    /** @internal */
    @cache
    static get information(): [number, number, number, number, number, number] {
        const snapshot = Il2Cpp.MemorySnapshot.capture();

        try {
            return Il2Cpp.Api._memorySnapshotGetRuntimeInformation(snapshot);
        } finally {
            Il2Cpp.Api._memorySnapshotFree(snapshot);
        }
    }

    /** Gets the pointer size. */
    static get pointerSize(): number {
        return this.information[0];
    }

    /** Gets the size of the Il2CppObject struct. */
    static get objectHeaderSize(): number {
        return this.information[1];
    }
}

Il2Cpp.Runtime = Il2CppRuntime;

declare global {
    namespace Il2Cpp {
        class Runtime extends Il2CppRuntime {}
    }
}
