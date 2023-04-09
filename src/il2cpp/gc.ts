namespace Il2Cpp {
    export class GC {
        protected constructor() {}

        /** Gets the heap size in bytes. */
        static get heapSize(): Int64 {
            return Il2Cpp.Api._gcGetHeapSize();
        }

        /** Determines whether the garbage collector is disabled. */
        static get isEnabled(): boolean {
            return !Il2Cpp.Api._gcIsDisabled();
        }

        /** Determines whether the garbage collector is incremental. */
        static get isIncremental(): boolean {
            return !!Il2Cpp.Api._gcIsIncremental();
        }

        /** Gets the number of nanoseconds the garbage collector can spend in a collection step. */
        static get maxTimeSlice(): Int64 {
            return Il2Cpp.Api._gcGetMaxTimeSlice();
        }

        /** Gets the used heap size in bytes. */
        static get usedHeapSize(): Int64 {
            return Il2Cpp.Api._gcGetUsedSize();
        }

        /** Enables or disables the garbage collector. */
        static set isEnabled(value: boolean) {
            value ? Il2Cpp.Api._gcEnable() : Il2Cpp.Api._gcDisable();
        }

        /** Sets the number of nanoseconds the garbage collector can spend in a collection step. */
        static set maxTimeSlice(nanoseconds: number | Int64) {
            Il2Cpp.Api._gcSetMaxTimeSlice(nanoseconds);
        }

        /** Returns the heap allocated objects of the specified class. This variant reads GC descriptors. */
        static choose(klass: Il2Cpp.Class): Il2Cpp.Object[] {
            const matches: Il2Cpp.Object[] = [];

            const callback = (objects: NativePointer, size: number) => {
                for (let i = 0; i < size; i++) {
                    matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
                }
            };

            const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);

            if (Versioning.gte(Il2Cpp.unityVersion, "2021.2.0")) {
                const realloc = (handle: NativePointer, size: UInt64) => {
                    if (!handle.isNull() && size.compare(0) == 0) {
                        Il2Cpp.free(handle);
                        return NULL;
                    } else {
                        return Il2Cpp.alloc(size);
                    }
                };

                const reallocCallback = new NativeCallback(realloc, "pointer", ["pointer", "size_t", "pointer"]);

                Il2Cpp.GC.stopWorld();

                const state = Il2Cpp.Api._livenessAllocateStruct(klass, 0, chooseCallback, NULL, reallocCallback);
                Il2Cpp.Api._livenessCalculationFromStatics(state);
                Il2Cpp.Api._livenessFinalize(state);

                Il2Cpp.GC.startWorld();

                Il2Cpp.Api._livenessFreeStruct(state);
            } else {
                const onWorld = new NativeCallback(() => {}, "void", []);
                const state = Il2Cpp.Api._livenessCalculationBegin(klass, 0, chooseCallback, NULL, onWorld, onWorld);

                Il2Cpp.Api._livenessCalculationFromStatics(state);
                Il2Cpp.Api._livenessCalculationEnd(state);
            }

            return matches;
        }

        /** Forces a garbage collection of the specified generation. */
        static collect(generation: 0 | 1 | 2): void {
            Il2Cpp.Api._gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
        }

        /** Forces a garbage collection. */
        static collectALittle(): void {
            Il2Cpp.Api._gcCollectALittle();
        }

        /** Resumes all the previously stopped threads. */
        static startWorld(): void {
            return Il2Cpp.Api._gcStartWorld();
        }

        /** Performs an incremental garbage collection. */
        static startIncrementalCollection(): void {
            return Il2Cpp.Api._gcStartIncrementalCollection();
        }

        /** Stops all threads which may access the garbage collected heap, other than the caller. */
        static stopWorld(): void {
            return Il2Cpp.Api._gcStopWorld();
        }
    }

    export namespace GC {
        export class Handle {
            /** @internal */
            constructor(readonly handle: number) {}

            /** Gets the object associated to this handle. */
            get target(): Il2Cpp.Object | null {
                const handle = Il2Cpp.Api._gcHandleGetTarget(this.handle);
                return handle.isNull() ? null : new Il2Cpp.Object(handle);
            }

            /** Frees this handle. */
            free(): void {
                return Il2Cpp.Api._gcHandleFree(this.handle);
            }
        }
    }
}
