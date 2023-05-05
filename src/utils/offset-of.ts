/** @internal */
interface NativePointer {
    offsetOf(condition: (handle: NativePointer) => boolean, depth?: number): number | null;
}

NativePointer.prototype.offsetOf = function (condition, depth) {
    depth ??= 512;

    for (let i = 0; i < depth; i++) {
        if (condition(this.add(i))) {
            return i;
        }
    }

    return null;
};
