import { NativeStruct } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";
import { readFieldValue, writeFieldValue } from "../utils";

@injectToIl2Cpp("Reference")
class Il2CppReference<T extends Il2Cpp.AllowedType = Il2Cpp.AllowedType> extends NativeStruct {
    constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
        super(handle);
    }

    set value(value: T) {
        writeFieldValue(this.handle, value, this.type);
    }

    get value(): T {
        return readFieldValue(this.handle, this.type) as T;
    }
}
