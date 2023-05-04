/** @internal */
function offsetOfPointer(handle: NativePointer, value: NativePointer): number {
    for (let i = 0; i < 512; i++) {
        if (handle.add(i).readPointer().equals(value)) {
            return i;
        }
    }
    return -1;
}

/** @internal */
function offsetOfInt32(handle: NativePointer, value: number): number {
    for (let i = 0; i < 512; i++) {
        if (handle.add(i).readS32() == value) {
            return i;
        }
    }
    return -1;
}
