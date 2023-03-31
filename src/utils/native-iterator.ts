/** @internal */
export function nativeIterator<T extends ObjectWrapper>(
    holder: NativePointerValue,
    nativeFunction: NativeFunction<NativePointer, [NativePointerValue, NativePointer]>,
    Class: new (handle: NativePointer) => T
): Array<T> {
    const array = new Array<T>();
    const iterator = Memory.alloc(Process.pointerSize);

    let handle: NativePointer;
    while (!(handle = nativeFunction(holder, iterator)).isNull()) {
        array.push(new Class(handle));
    }

    return array;
}
