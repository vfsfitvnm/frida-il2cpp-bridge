import { raise } from "./console";

/** Scaffold class. */
export class NativeStruct {
    constructor(readonly handle: NativePointer) {}

    equals(other: NativeStruct) {
        return this.handle.equals(other.handle);
    }
}

/** Scaffold class whom pointer cannot be null.. */
export class NativeStructNotNull extends NativeStruct {
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
