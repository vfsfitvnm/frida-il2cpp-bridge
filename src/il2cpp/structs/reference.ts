import { checkNull } from "../decorators";
import { read, write } from "../utils";

import { NativeStruct } from "../../utils/native-struct";

/** Represent a parameter passed by reference. */
class Il2CppReference<T extends Il2Cpp.Field.Type> extends NativeStruct {
    /** @internal */
    constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
        super(handle);
    }

    /** */
    get value(): T {
        return read(this.handle, this.type) as T;
    }

    /** */
    set value(value: T) {
        write(this.handle, value, this.type);
    }

    @checkNull
    override toString(): string {
        return `->${this.value}`;
    }
}

Il2Cpp.Reference = Il2CppReference;

declare global {
    namespace Il2Cpp {
        class Reference<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends Il2CppReference<T> {}
    }
}
