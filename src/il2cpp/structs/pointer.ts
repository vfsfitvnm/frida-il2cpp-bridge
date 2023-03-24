import { read, write } from "../utils.js";
import { NativeStruct } from "../../utils/native-struct.js";

/** */
class Il2CppPointer<T extends Il2Cpp.Field.Type> extends NativeStruct {
    constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
        super(handle);
    }

    /** Gets the element at the given index. */
    get(index: number): T {
        return read(this.handle.add(index * this.type.class.arrayElementSize), this.type) as T;
    }

    /** Reads the given amount of elements starting at the given offset. */
    read(length: number, offset: number = 0): T[] {
        const values = new Array<T>(length);

        for (let i = 0; i < length; i++) {
            values[i] = this.get(i + offset);
        }

        return values;
    }

    /** Sets the given element at the given index */
    set(index: number, value: T): void {
        write(this.handle.add(index * this.type.class.arrayElementSize), value, this.type);
    }

    /** */
    toString(): string {
        return this.handle.toString();
    }

    /** Writes the given elements starting at the given index. */
    write(values: T[], offset: number = 0): void {
        for (let i = 0; i < values.length; i++) {
            this.set(i + offset, values[i]);
        }
    }
}

Il2Cpp.Pointer = Il2CppPointer;

declare global {
    namespace Il2Cpp {
        class Pointer<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends Il2CppPointer<T> {}
    }
}
