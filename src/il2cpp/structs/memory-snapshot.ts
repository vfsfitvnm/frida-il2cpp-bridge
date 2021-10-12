import { cache } from "decorator-cache-getter";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { IterableRecord, makeRecordFromNativeIterator } from "../../utils/utils";

/** Represents a `Il2CppManagedMemorySnapshot`. */
class Il2CppMemorySnapshot extends NonNullNativeStruct {
    /** Captures a memory snapshot. */
    static capture(): Il2Cpp.MemorySnapshot {
        return new Il2Cpp.MemorySnapshot();
    }

    /** Creates a memory snapshot with the given handle. */
    constructor(handle: NativePointer = Il2Cpp.Api._memorySnapshotCapture()) {
        super(handle);
    }

    /** Gets any initialized class. */
    @cache
    get classes(): IterableRecord<Il2Cpp.Class> {
        return makeRecordFromNativeIterator(this, Il2Cpp.Api._memorySnapshotGetClasses, Il2Cpp.Class, klass => klass.type.name);
    }

    /** Gets the objects tracked by this memory snapshot. */
    @cache
    get objects(): Il2Cpp.Object[] {
        const array: Il2Cpp.Object[] = [];

        const [count, start] = Il2Cpp.Api._memorySnapshotGetGCHandles(this);

        for (let i = 0; i < count; i++) {
            array.push(new Il2Cpp.Object(start.add(i * Process.pointerSize).readPointer()));
        }

        return array;
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
