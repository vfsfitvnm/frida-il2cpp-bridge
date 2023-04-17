namespace Il2Cpp {
    export class Runtime {
        /** Gets the allocation granularity, it should be `Process.pointerSize * 2`. */
        static get allocationGranularity(): number {
            return this.information[5];
        }

        /** @internal */
        @lazy
        static get information(): [number, number, number, number, number, number] {
            return Il2Cpp.MemorySnapshot.use(Il2Cpp.Api.memorySnapshotGetRuntimeInformation);
        }

        /** Gets the pointer size. */
        static get pointerSize(): number {
            return this.information[0];
        }

        /** @internal */
        static internalCall<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(name: string, retType: R, argTypes: A) {
            const handle = Il2Cpp.Api.resolveInternalCall(Memory.allocUtf8String(name));
            return handle.isNull() ? null : new NativeFunction<R, A>(handle, retType, argTypes);
        }
    }
}
