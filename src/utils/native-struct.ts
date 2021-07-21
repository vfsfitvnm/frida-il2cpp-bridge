import { raise } from "./console";

/** Scaffold class. */
export class NativeStruct implements ObjectWrapper {
    readonly handle: NativePointer;

    constructor(handle: NativePointer);
    constructor(wrapper: ObjectWrapper);
    constructor(handleOrWrapper: NativePointer | ObjectWrapper) {
        if (handleOrWrapper instanceof NativePointer) {
            this.handle = handleOrWrapper;
        } else {
            this.handle = handleOrWrapper.handle;
        }
    }

    equals(other: NativeStruct) {
        return this.handle.equals(other.handle);
    }
}

/** Scaffold class whom pointer cannot be null. */
export class NonNullNativeStruct extends NativeStruct {
    constructor(handle: NativePointer) {
        super(handle);

        if (handle.isNull()) {
            raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }
    }
}

/** @internal */
export function getOrNull<T extends NativeStruct>(handle: NativePointer, Class: new (...args: any[]) => T): T | null {
    return handle.isNull() ? null : new Class(handle);
}
