/** @internal */
function nativeIterator<T extends ObjectWrapper>(
    holder: NativePointerValue,
    nativeFunction: NativeFunction<NativePointer, [NativePointerValue, NativePointer]>,
    Class: new (handle: NativePointer) => T
): T[] {
    const array = [];
    const iterator = Memory.alloc(Process.pointerSize);

    let handle: NativePointer;
    while (!(handle = nativeFunction(holder, iterator)).isNull()) {
        array.push(new Class(handle));
    }

    return array;
}
