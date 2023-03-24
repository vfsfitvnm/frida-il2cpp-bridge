/** @internal */
export function* nativeIterator<T extends ObjectWrapper>(
    holder: NativePointerValue,
    nativeFunction: NativeFunction<NativePointer, [NativePointerValue, NativePointer]>,
    Class: new (handle: NativePointer) => T
): Generator<T> {
    const iterator = Memory.alloc(Process.pointerSize);
    let handle: NativePointer;

    while (!(handle = nativeFunction(holder, iterator)).isNull()) {
        yield new Class(handle);
    }
}

/** @internal */
export function cacheInstances<T extends ObjectWrapper, U extends new (handle: NativePointer) => T>(Class: U) {
    const instanceCache = new Map<number, T>();

    return new Proxy(Class, {
        construct(Target: U, argArray: [NativePointer]): T {
            const handle = argArray[0].toUInt32();

            if (!instanceCache.has(handle)) {
                instanceCache.set(handle, new Target(argArray[0]));
            }
            return instanceCache.get(handle)!;
        }
    });
}
