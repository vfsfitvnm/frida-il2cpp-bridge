/** Scaffold class. */
class NativeStruct implements ObjectWrapper {
    readonly handle: NativePointer;

    constructor(handleOrWrapper: NativePointerValue) {
        if (handleOrWrapper instanceof NativePointer) {
            this.handle = handleOrWrapper;
        } else {
            this.handle = handleOrWrapper.handle;
        }
    }

    equals(other: NativeStruct) {
        return this.handle.equals(other.handle);
    }

    isNull(): boolean {
        return this.handle.isNull();
    }

    asNullable(): this | null {
        return this.isNull() ? null : this;
    }
}
