/** @internal */
export function filterMapArray<V, U>(source: V[], filter: (value: V) => boolean, map: (value: V) => U): U[] {
    const dest: U[] = [];

    for (const value of source) {
        if (filter(value)) {
            dest.push(map(value));
        }
    }

    return dest;
}

/** @internal */
export function mapToArray<V, U>(source: V[], map: (value: V) => U): U[] {
    const dest: U[] = [];

    for (const value of source) {
        dest.push(map(value));
    }

    return dest;
}

/** @internal */
export function formatNativePointer(nativePointer: NativePointer): string {
    return `0x${nativePointer.toString(16).padStart(8, "0")}`;
}

/** @internal */
export function getOrNull<T extends ObjectWrapper>(handle: NativePointer, Class: new (handle: NativePointer) => T): T | null {
    return handle.isNull() ? null : new Class(handle);
}

/** @internal */
export function *nativeIterator<T extends ObjectWrapper>(
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

/** @internal */
export function memoize(_: any, __: string, descriptor: PropertyDescriptor) {
    if (descriptor.value != null) {
        const map = new Map<string, any>();
        const original = descriptor.value;

        descriptor.value = function (...args: any[]): any {
            const key = args.toString();
            if (!map.has(key)) {
                const result = original.apply(this, args);
                if (result) {
                    map.set(key, result);
                }
            }
            return map.get(key);
        };
    }
}
