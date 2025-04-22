/** @internal */
function readNativeList(block: (lengthPointer: NativePointer) => NativePointer): NativePointer[] {
    const lengthPointer = Memory.alloc(Process.pointerSize);
    const startPointer = block(lengthPointer);

    if (startPointer.isNull()) {
        return [];
    }

    const array = new Array(lengthPointer.readInt());

    for (let i = 0; i < array.length; i++) {
        array[i] = startPointer.add(i * Process.pointerSize).readPointer();
    }

    return array;
}
