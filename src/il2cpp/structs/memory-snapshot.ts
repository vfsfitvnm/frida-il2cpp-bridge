import { cache } from "decorator-cache-getter";

import { Api } from "il2cpp/api";
import { nonNullHandle } from "il2cpp/decorators";
import { NativeStruct } from "il2cpp/native-struct";

/**
 * Represents a `Il2CppMemorySnapshot`.
 */
@nonNullHandle
export class _Il2CppMemorySnapshot extends NativeStruct {
    constructor() {
        super(Api._memorySnapshotCapture());
    }

    @cache get trackedObjectCount() {
        return Api._memorySnapshotGetTrackedObjectCount(this.handle);
    }

    @cache get objectsPointer() {
        return Api._memorySnapshotGetObjects(this.handle);
    }

    free() {
        Api._memorySnapshotFree(this.handle);
    }
}
