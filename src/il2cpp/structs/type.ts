import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { nonNullHandle } from "../decorators";
import { NativeStruct } from "../native-struct";
import { getOrNull } from "../utils";

import { _Il2CppClass } from "./class";
import { _Il2CppGenericClass } from "./generic-class";
import { _Il2CppTypeEnum } from "./type-enum";

/**
 * Represents a `Il2CppType`.
 */
@nonNullHandle
export class _Il2CppType extends NativeStruct {
    /** @internal */
    @cache static get offsetOfTypeEnum() {
        return Api._typeOffsetOfTypeEnum();
    }

    /** @internal */
    @cache get aliasForFrida() {
        switch (this.typeEnum) {
            case _Il2CppTypeEnum.VOID:
                return "void";
            case _Il2CppTypeEnum.BOOLEAN:
                return "bool";
            case _Il2CppTypeEnum.CHAR:
                return "char";
            case _Il2CppTypeEnum.I1:
                return "int8";
            case _Il2CppTypeEnum.U1:
                return "uint8";
            case _Il2CppTypeEnum.I2:
                return "int16";
            case _Il2CppTypeEnum.U2:
                return "uint16";
            case _Il2CppTypeEnum.I4:
                return "int32";
            case _Il2CppTypeEnum.U4:
                return "uint32";
            case _Il2CppTypeEnum.I8:
                return "int64";
            case _Il2CppTypeEnum.U8:
                return "uint64";
            case _Il2CppTypeEnum.R4:
                return "float";
            case _Il2CppTypeEnum.R8:
                return "double";
            default:
                return "pointer";
        }
    }

    /**
     * @return Its class.
     */
    @cache get class() {
        return new _Il2CppClass(Api._classFromType(this.handle));
    }

    /**
     * @return If it's an array, the type of its elements, `null` otherwise.
     */
    @cache get dataType() {
        return getOrNull(Api._typeGetDataType(this.handle), _Il2CppType);
    }

    /**
     * @returns If it's a generic type, its generic class, `null` otherwise.
     */
    @cache get genericClass() {
        return getOrNull(Api._typeGetGenericClass(this.handle), _Il2CppGenericClass);
    }

    /**
     *  @returns `true` if it's passed by reference, `false` otherwise.
     */
    @cache get isByReference() {
        return Api._typeIsByReference(this.handle);
    }

    /**
     * @returns Its name, namespace included and declaring class excluded. If its class is nested,
     * it corresponds to the class name.
     */
    @cache get name() {
        return Api._typeGetName(this.handle)!;
    }

    /**
     * @returns Its corresponding type.
     */
    @cache get typeEnum() {
        return Api._typeGetTypeEnum(this.handle) as _Il2CppTypeEnum;
    }
}
