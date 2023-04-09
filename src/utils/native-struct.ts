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
}

/** Scaffold class whom pointer cannot be null. */
class NonNullNativeStruct extends NativeStruct {
    constructor(handle: NativePointer) {
        super(handle);

        if (handle.isNull()) {
            throw new Error(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }
    }
}
