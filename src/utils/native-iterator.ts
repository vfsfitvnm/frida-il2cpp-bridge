/** @internal */
function nativeIterator(block: (iterator: NativePointer) => NativePointer): NativePointer[] {
    const array = [];
    const iterator = Memory.alloc(Process.pointerSize);

    let handle = block(iterator);
    while (!handle.isNull()) {
        array.push(handle);
        handle = block(iterator);
    }

    return array;
}
