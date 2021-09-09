import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { filterMapArray, getOrNull } from "../../utils/utils";
import { warn } from "../../utils/console";

/** Represents a `Il2CppType`. */
class Il2CppType extends NonNullNativeStruct {
    /** Gets the class of this type. */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._classFromType(this));
    }

    /** Gets the encompassed type of this array type. */
    @cache
    get dataType(): Il2Cpp.Type | null {
        return getOrNull(Il2Cpp.Api._typeGetDataType(this), Il2Cpp.Type);
    }

    /** */
    @cache
    get fridaAlias(): NativeCallbackArgumentType {
        if (this.isByReference) {
            return "pointer";
        }

        switch (this.typeEnum) {
            case Il2Cpp.Type.Enum.Void:
                return "void";
            case Il2Cpp.Type.Enum.Boolean:
                return "bool";
            case Il2Cpp.Type.Enum.Char:
                return "uchar";
            case Il2Cpp.Type.Enum.I1:
                return "int8";
            case Il2Cpp.Type.Enum.U1:
                return "uint8";
            case Il2Cpp.Type.Enum.I2:
                return "int16";
            case Il2Cpp.Type.Enum.U2:
                return "uint16";
            case Il2Cpp.Type.Enum.I4:
                return "int32";
            case Il2Cpp.Type.Enum.U4:
                return "uint32";
            case Il2Cpp.Type.Enum.I8:
                return "int64";
            case Il2Cpp.Type.Enum.U8:
                return "uint64";
            case Il2Cpp.Type.Enum.R4:
                return "float";
            case Il2Cpp.Type.Enum.R8:
                return "double";
            case Il2Cpp.Type.Enum.ValueType:
                return getValueTypeFields(this);
            case Il2Cpp.Type.Enum.NativeInteger:
            case Il2Cpp.Type.Enum.NativeUnsignedInteger:
            case Il2Cpp.Type.Enum.Pointer:
            case Il2Cpp.Type.Enum.String:
            case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
            case Il2Cpp.Type.Enum.Array:
                return "pointer";
            case Il2Cpp.Type.Enum.Class:
            case Il2Cpp.Type.Enum.Object:
            case Il2Cpp.Type.Enum.GenericInstance:
                return this.class.isValueType ? getValueTypeFields(this) : "pointer";
            default:
                warn(`fridaAlias: defaulting ${this.name}, "${this.typeEnum}" to pointer`);
                return "pointer";
        }
    }

    /** */
    @cache
    get genericClass(): Il2Cpp.GenericClass {
        return new Il2Cpp.GenericClass(Il2Cpp.Api._typeGetGenericClass(this));
    }

    /** Determines whether this type is passed by reference. */
    @cache
    get isByReference(): boolean {
        return !!Il2Cpp.Api._typeIsByReference(this);
    }

    /** Gets the name of this type. */
    @cache
    get name(): string {
        return Il2Cpp.Api._typeGetName(this).readUtf8String()!;
    }

    /** Gets the encompassing object of the current type. */
    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(Il2Cpp.Api._typeGetObject(this));
    }

    /** */
    @cache
    get typeEnum(): Il2Cpp.Type.Enum {
        return Il2Cpp.Api._typeGetTypeEnum(this);
    }
}

function getValueTypeFields(type: Il2Cpp.Type): NativeCallbackArgumentType {
    return filterMapArray(
        type.class.fields,
        (field: Il2Cpp.Field) => !field.isStatic,
        (field: Il2Cpp.Field) => field.type.fridaAlias
    );
}

Reflect.set(Il2Cpp, "Type", Il2CppType);

declare global {
    namespace Il2Cpp {
        class Type extends Il2CppType {}
    }
}
