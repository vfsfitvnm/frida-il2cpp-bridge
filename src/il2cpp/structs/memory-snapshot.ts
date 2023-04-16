namespace Il2Cpp {
    export class MemorySnapshot extends NonNullNativeStruct {
        /** Captures a memory snapshot. */
        static capture(): Il2Cpp.MemorySnapshot {
            return new Il2Cpp.MemorySnapshot();
        }

        /** */
        static use<T>(block: (memorySnapshot: Omit<Il2Cpp.MemorySnapshot, "free">) => T): T {
            const memorySnapshot = this.capture();
            const result = block(memorySnapshot);
            memorySnapshot.free();
            return result;
        }

        /** Creates a memory snapshot with the given handle. */
        constructor(handle: NativePointer = Il2Cpp.Api._memorySnapshotCapture()) {
            super(handle);
        }

        /** Gets any initialized class. */
        @lazy
        get classes(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.Api._memorySnapshotGetClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the objects tracked by this memory snapshot. */
        @lazy
        get objects(): Il2Cpp.Object[] {
            const array: Il2Cpp.Object[] = [];

            const [count, start] = Il2Cpp.Api._memorySnapshotGetGCHandles(this);

            for (let i = 0; i < count; i++) {
                const handle = start.add(i * Process.pointerSize).readPointer();
                if (!handle.isNull()) {
                    array.push(new Il2Cpp.Object(handle));
                }
            }

            return array;
        }

        /** Frees this memory snapshot. */
        free(): void {
            Il2Cpp.Api._memorySnapshotFree(this);
        }
    }
}
