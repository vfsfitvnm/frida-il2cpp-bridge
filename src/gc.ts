namespace Il2Cpp {
    /**
     * The object literal to interacts with the garbage collector.
     */
    export const gc = {
        /**
         * Gets the heap size in bytes.
         */
        get heapSize(): Int64 {
            return Il2Cpp.api.gcGetHeapSize();
        },

        /**
         * Determines whether the garbage collector is enabled.
         */
        get isEnabled(): boolean {
            return !Il2Cpp.api.gcIsDisabled();
        },

        /**
         * Determines whether the garbage collector is incremental
         * ([source](https://docs.unity3d.com/Manual/performance-incremental-garbage-collection.html)).
         */
        get isIncremental(): boolean {
            return !!Il2Cpp.api.gcIsIncremental();
        },

        /**
         * Gets the number of nanoseconds the garbage collector can spend in a
         * collection step.
         */
        get maxTimeSlice(): Int64 {
            return Il2Cpp.api.gcGetMaxTimeSlice();
        },

        /**
         * Gets the used heap size in bytes.
         */
        get usedHeapSize(): Int64 {
            return Il2Cpp.api.gcGetUsedSize();
        },

        /**
         * Enables or disables the garbage collector.
         */
        set isEnabled(value: boolean) {
            value ? Il2Cpp.api.gcEnable() : Il2Cpp.api.gcDisable();
        },

        /**
         *  Sets the number of nanoseconds the garbage collector can spend in
         * a collection step.
         */
        set maxTimeSlice(nanoseconds: number | Int64) {
            Il2Cpp.api.gcSetMaxTimeSlice(nanoseconds);
        },

        /**
         * Returns the heap allocated objects of the specified class. \
         * This variant reads GC descriptors.
         */
        choose(klass: Il2Cpp.Class): Il2Cpp.Object[] {
            const matches: Il2Cpp.Object[] = [];

            const callback = (objects: NativePointer, size: number) => {
                for (let i = 0; i < size; i++) {
                    matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
                }
            };

            const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);

            if (Il2Cpp.unityVersionIsBelow202120) {
                const onWorld = new NativeCallback(() => {}, "void", []);
                const state = Il2Cpp.api.livenessCalculationBegin(klass, 0, chooseCallback, NULL, onWorld, onWorld);

                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessCalculationEnd(state);
            } else {
                const realloc = (handle: NativePointer, size: UInt64) => {
                    if (!handle.isNull() && size.compare(0) == 0) {
                        Il2Cpp.free(handle);
                        return NULL;
                    } else {
                        return Il2Cpp.alloc(size);
                    }
                };

                const reallocCallback = new NativeCallback(realloc, "pointer", ["pointer", "size_t", "pointer"]);

                this.stopWorld();

                const state = Il2Cpp.api.livenessAllocateStruct(klass, 0, chooseCallback, NULL, reallocCallback);
                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessFinalize(state);

                this.startWorld();

                Il2Cpp.api.livenessFreeStruct(state);
            }

            return matches;
        },

        /**
         * Forces a garbage collection of the specified generation.
         */
        collect(generation: 0 | 1 | 2): void {
            Il2Cpp.api.gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
        },

        /**
         * Forces a garbage collection.
         */
        collectALittle(): void {
            Il2Cpp.api.gcCollectALittle();
        },

        /**
         *  Resumes all the previously stopped threads.
         */
        startWorld(): void {
            return Il2Cpp.api.gcStartWorld();
        },

        /**
         * Performs an incremental garbage collection.
         */
        startIncrementalCollection(): void {
            return Il2Cpp.api.gcStartIncrementalCollection();
        },

        /**
         * Stops all threads which may access the garbage collected heap, other
         * than the caller.
         */
        stopWorld(): void {
            return Il2Cpp.api.gcStopWorld();
        }
    };
}
