import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppMemorySnapshot`. */
class Il2CppMemorySnapshot extends NonNullNativeStruct {
    /** Captures a memory snapshot. */
    static capture(): Il2Cpp.MemorySnapshot {
        return new Il2Cpp.MemorySnapshot(Il2Cpp.Api._memorySnapshotCapture());
    }

    /** */
    @cache
    get metadataSnapshot(): Il2Cpp.MetadataSnapshot {
        return new Il2Cpp.MetadataSnapshot(Il2Cpp.Api._memorySnapshotGetMetadataSnapshot(this));
    }

    /** Gets the objects tracked by this memory snapshot. */
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

    /** Gets a pointer to the first object tracked in this memory snapshot. */
    @cache
    get objectsPointer(): NativePointer {
        return Il2Cpp.Api._memorySnapshotGetObjects(this);
    }

    /** Gets the amount of objects tracked in this memory snapshot. */
    @cache
    get trackedObjectCount(): UInt64 {
        return Il2Cpp.Api._memorySnapshotGetTrackedObjectCount(this);
    }

    /** Frees this memory snapshot. */
    free(): void {
        Il2Cpp.Api._memorySnapshotFree(this);
    }
}

Il2Cpp.MemorySnapshot = Il2CppMemorySnapshot;

declare global {
    namespace Il2Cpp {
        class MemorySnapshot extends Il2CppMemorySnapshot {}
    }
}
