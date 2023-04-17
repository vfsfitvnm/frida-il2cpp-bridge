namespace Il2Cpp {
    export class Runtime {
        /** Gets the allocation granularity. */
        static get allocationGranularity(): number {
            return this.information[5];
        }

        /** @internal */
        @lazy
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

        /** @internal */
        static internalCall<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(name: string, retType: R, argTypes: A) {
            const handle = Il2Cpp.Api._resolveInternalCall(Memory.allocUtf8String(name));
            return handle.isNull() ? null : new NativeFunction<R, A>(handle, retType, argTypes);
        }
    }
}
