/** @internal */
interface NativePointer {
    offsetOf(condition: (handle: NativePointer) => boolean, depth?: number): number | null;
}

NativePointer.prototype.offsetOf = function (condition, depth) {
    depth ??= 512;

    for (let i = 0; depth > 0 ? i < depth : i < -depth; i++) {
        if (condition(depth > 0 ? this.add(i) : this.sub(i))) {
            return i;
        }
    }

    return null;
};
