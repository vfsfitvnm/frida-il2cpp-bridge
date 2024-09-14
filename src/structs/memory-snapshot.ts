namespace Il2Cpp {
    export class MemorySnapshot extends NativeStruct {
        /** Captures a memory snapshot. */
        static capture(): Il2Cpp.MemorySnapshot {
            return new Il2Cpp.MemorySnapshot();
        }

        /** Creates a memory snapshot with the given handle. */
        constructor(handle: NativePointer = Il2Cpp.exports.memorySnapshotCapture()) {
            super(handle);
        }

        /** Gets any initialized class. */
        @lazy
        get classes(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.exports.memorySnapshotGetClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the objects tracked by this memory snapshot. */
        @lazy
        get objects(): Il2Cpp.Object[] {
            // prettier-ignore
            return readNativeList(_ => Il2Cpp.exports.memorySnapshotGetObjects(this, _)).filter(_ => !_.isNull()).map(_ => new Il2Cpp.Object(_));
        }

        /** Frees this memory snapshot. */
        free(): void {
            Il2Cpp.exports.memorySnapshotFree(this);
        }
    }

    /** */
    export function memorySnapshot<T>(block: (memorySnapshot: Omit<Il2Cpp.MemorySnapshot, "free">) => T): T {
        const memorySnapshot = Il2Cpp.MemorySnapshot.capture();
        const result = block(memorySnapshot);
        memorySnapshot.free();
        return result;
    }
}
