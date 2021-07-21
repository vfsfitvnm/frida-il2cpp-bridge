import { cache } from "decorator-cache-getter";

import { raise } from "../../utils/console";

import { Api } from "../api";
import { injectToIl2Cpp, shouldBeInstance } from "../decorators";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { readFieldValue, writeFieldValue } from "../utils";

@injectToIl2Cpp("Field")
class Il2CppField extends NonNullNativeStruct {
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._fieldGetClass(this));
    }

    @cache
    get isLiteral(): boolean {
        return Api._fieldIsLiteral(this);
    }

    @cache
    get isStatic(): boolean {
        return !Api._fieldIsInstance(this);
    }

    @cache
    get isThreadStatic(): boolean {
        return this.offset == -1;
    }

    @cache
    get name(): string {
        return Api._fieldGetName(this)!;
    }

    @cache
    get offset(): number {
        return Api._fieldGetOffset(this);
    }

    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._fieldGetType(this));
    }

    get value(): Il2Cpp.AllowedType {
        return readFieldValue(this.valueHandle, this.type);
    }

    @shouldBeInstance(false)
    set value(value: Il2Cpp.AllowedType) {
        if (this.isThreadStatic || this.isLiteral) {
            raise(`Cannot edit the thread static or literal field "${this.name}".`);
        }

        writeFieldValue(this.valueHandle, value, this.type);
    }

    @shouldBeInstance(false)
    get valueHandle(): NativePointer {
        const value = Memory.alloc(Process.pointerSize);
        Api._fieldGetStaticValue(this, value);
        return value;
    }

    @shouldBeInstance(true)
    asHeld(handle: NativePointer): Il2Cpp.WithValue {
        const type = this.type;

        return {
            valueHandle: handle,
            get value(): Il2Cpp.AllowedType {
                return readFieldValue(handle, type);
            },
            set value(value: Il2Cpp.AllowedType) {
                writeFieldValue(handle, value, type);
            }
        } as Il2Cpp.WithValue;
    }
}
