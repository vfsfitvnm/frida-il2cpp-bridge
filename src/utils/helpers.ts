/** @internal */
export const getOrNull = <T>(handle: NativePointer, target: new (handle: NativePointer) => T) =>
    handle.isNull() ? null : new target(handle);
