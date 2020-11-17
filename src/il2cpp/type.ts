import Api from "./api";
import { lazy } from "../utils/decorators";
import { getOrNull } from "../utils/helpers";
import Il2CppClass from "./class";
import Il2CppGenericClass from "./generic-class";
import { raise } from "../utils/console";
import Il2CppTypeEnum from "./type-enum";

/** @internal */
export default class Il2CppType {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy
    static get offsetOfTypeEnum() {
        return Api._typeOffsetOfTypeEnum();
    }

    @lazy get aliasForFrida() {
        switch (this.typeEnum) {
            case Il2CppTypeEnum.VOID:
                return "void";
            case Il2CppTypeEnum.BOOLEAN:
                return "bool";
            case Il2CppTypeEnum.CHAR:
                return "char";
            case Il2CppTypeEnum.I1:
                return "int8";
            case Il2CppTypeEnum.U1:
                return "uint8";
            case Il2CppTypeEnum.I2:
                return "int16";
            case Il2CppTypeEnum.U2:
                return "uint16";
            case Il2CppTypeEnum.I4:
                return "int32";
            case Il2CppTypeEnum.U4:
                return "uint32";
            case Il2CppTypeEnum.I8:
                return "int64";
            case Il2CppTypeEnum.U8:
                return "uint64";
            case Il2CppTypeEnum.R4:
                return "float";
            case Il2CppTypeEnum.R8:
                return "double";
            default:
                return "pointer";
        }
    }

    @lazy get class() {
        return new Il2CppClass(Api._classFromType(this.handle));
    }

    @lazy get dataType() {
        return getOrNull(Api._typeGetDataType(this.handle), Il2CppType);
    }

    @lazy get genericClass() {
        return getOrNull(Api._typeGetGenericClass(this.handle), Il2CppGenericClass);
    }

    @lazy get isByReference() {
        return Api._typeIsByReference(this.handle);
    }

    @lazy get name() {
        return Api._typeGetName(this.handle)!;
    }

    @lazy get typeEnum() {
        return Api._typeGetTypeEnum(this.handle) as Il2CppTypeEnum;
    }
}
