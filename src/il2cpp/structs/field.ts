import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp, shouldBeInstance } from "../decorators";
import { readFieldValue, writeFieldValue } from "../utils";

import { warn } from "../../utils/console";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { redefineProperty } from "../../utils/record";

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

    @shouldBeInstance(false)
    get value(): Il2Cpp.Field.Type {
        const value = Memory.alloc(Process.pointerSize);
        Api._fieldGetStaticValue(this, value);
        return readFieldValue(value, this.type);
    }

    set value(value: Il2Cpp.Field.Type) {
        if (this.isThreadStatic || this.isLiteral) {
            warn(`${this.class.type.name}.\x1b[1m${this.name}\x1b[0m is a thread static or literal field, its value won't be modified.`);
        }

        const valueHandle = Memory.alloc(Process.pointerSize);
        writeFieldValue(valueHandle, value, this.type);
        Api._fieldSetStaticValue(this, valueHandle);
    }

    @shouldBeInstance(true)
    withHolder(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.Field {
        let valueHandle = instance.handle.add(this.offset);
        if (instance instanceof Il2Cpp.ValueType) {
            valueHandle = valueHandle.sub(Il2Cpp.Object.headerSize);
        }

        return redefineProperty(new Il2Cpp.Field(this.handle), "value", {
            get: (): Il2Cpp.Field.Type => {
                return readFieldValue(valueHandle, this.type);
            },
            set: (value: Il2Cpp.Field.Type) => {
                writeFieldValue(valueHandle, value, this.type);
            }
        });
    }
}
