import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { getOrNull, NonNullNativeStruct } from "../../utils/native-struct";
import { filterMapArray } from "../../utils/utils";
import { warn } from "../../utils/console";

@injectToIl2Cpp("Type")
class Il2CppType extends NonNullNativeStruct {
    @cache
    static get offsetOfTypeEnum() {
        return Api._typeOffsetOfTypeEnum();
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._classFromType(this));
    }

    @cache
    get dataType(): Il2Cpp.Type | null {
        return getOrNull(Api._typeGetDataType(this), Il2Cpp.Type);
    }

    @cache
    get fridaAlias(): NativeCallbackArgumentType {
        if (this.isByReference) {
            return "pointer";
        }

        switch (this.typeEnum) {
            case "void":
                return "void";
            case "boolean":
                return "bool";
            case "char":
                return "uchar";
            case "i1":
                return "int8";
            case "u1":
                return "uint8";
            case "i2":
                return "int16";
            case "u2":
                return "uint16";
            case "i4":
                return "int32";
            case "u4":
                return "uint32";
            case "i8":
                return "int64";
            case "u8":
                return "uint64";
            case "r4":
                return "float";
            case "r8":
                return "double";
            case "valuetype":
                return filterMapArray(
                    this.class.fields,
                    (field: Il2Cpp.Field) => !field.isStatic,
                    (field: Il2Cpp.Field) => field.type.fridaAlias
                );
            case "i":
            case "u":
            case "ptr":
            case "string":
            case "szarray":
            case "array":
            case "class":
            case "object":
            case "genericinst":
                return "pointer";
            default:
                warn(`fridaAlias: defaulting ${this.name}, "${this.typeEnum}" to pointer`);
                return "pointer";
        }
    }

    @cache
    get isByReference(): boolean {
        return !!Api._typeIsByReference(this);
    }

    @cache
    get name(): string {
        return Api._typeGetName(this).readUtf8String()!;
    }

    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._typeGetObject(this));
    }

    @cache
    get typeEnum(): Il2Cpp.Type.Enum {
        switch (Api._typeGetTypeEnum(this)) {
            case 0x00:
                return "end";
            case 0x01:
                return "void";
            case 0x02:
                return "boolean";
            case 0x03:
                return "char";
            case 0x04:
                return "i1";
            case 0x05:
                return "u1";
            case 0x06:
                return "i2";
            case 0x07:
                return "u2";
            case 0x08:
                return "i4";
            case 0x09:
                return "u4";
            case 0x0a:
                return "i8";
            case 0x0b:
                return "u8";
            case 0x0c:
                return "r4";
            case 0x0d:
                return "r8";
            case 0x0e:
                return "string";
            case 0x0f:
                return "ptr";
            case 0x10:
                return "byref";
            case 0x11:
                return "valuetype";
            case 0x12:
                return "class";
            case 0x13:
                return "var";
            case 0x14:
                return "array";
            case 0x15:
                return "genericinst";
            case 0x16:
                return "typedbyref";
            case 0x18:
                return "i";
            case 0x19:
                return "u";
            case 0x1b:
                return "fnptr";
            case 0x1c:
                return "object";
            case 0x1d:
                return "szarray";
            case 0x1e:
                return "mvar";
            case 0x1f:
                return "cmod_reqd";
            case 0x20:
                return "cmod_opt";
            case 0x21:
                return "internal";
            case 0x40:
                return "modifier";
            case 0x41:
                return "sentinel";
            case 0x45:
                return "pinned";
            case 0x55:
                return "enum";
            default:
                return "end";
        }
    }
}
