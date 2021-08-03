import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("MemorySnapshot")
class Il2CppMemorySnapshot extends NonNullNativeStruct {
    static capture(): Il2Cpp.MemorySnapshot {
        return new Il2Cpp.MemorySnapshot(Api._memorySnapshotCapture());
    }

    @cache
    get metadataSnapshot(): Il2Cpp.MetadataSnapshot {
        return new Il2Cpp.MetadataSnapshot(Api._memorySnapshotGetMetadataSnapshot(this));
    }

    @cache
    get objects(): Il2Cpp.Object[] {
        const objects: Il2Cpp.Object[] = [];

        const count = this.trackedObjectCount.toNumber();
        const start = this.objectsPointer;

        for (let i = 0; i < count; i++) {
            objects.push(new Il2Cpp.Object(start.add(i * Process.pointerSize).readPointer()));
        }

        return objects;
    }

    @cache
    get objectsPointer(): NativePointer {
        return Api._memorySnapshotGetObjects(this);
    }

    @cache
    get trackedObjectCount(): UInt64 {
        return Api._memorySnapshotGetTrackedObjectCount(this);
    }

    free(): void {
        Api._memorySnapshotFree(this);
    }
}
