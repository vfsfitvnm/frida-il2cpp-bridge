import { Il2CppValueType } from "./structs/value-type";
import { Il2CppObject } from "./structs/object";
import { Il2CppString } from "./structs/string";
import { Il2CppArray } from "./structs/array";
import { inform, ok, raise } from "../utils/console";
import { Il2CppType } from "./structs/type";
import { Il2CppTypeEnum } from "./structs/type-enum";
import { AllowedType } from "./types";
import { NativeStruct } from "./native-struct";
import { domain } from "./variables";

/** @internal */
export function getOrNull<T extends NativeStruct>(handle: NativePointer, Class: new (...args: any[]) => T) {
    return handle.isNull() ? null : new Class(handle);
}

/** @internal */
function isCoherent(value: AllowedType, type: Il2CppType) {
    switch (type.typeEnum) {
        case Il2CppTypeEnum.VOID:
            return value == undefined;
        case Il2CppTypeEnum.BOOLEAN:
            return typeof value == "boolean";
        case Il2CppTypeEnum.I1:
        case Il2CppTypeEnum.U1:
        case Il2CppTypeEnum.I2:
        case Il2CppTypeEnum.U2:
        case Il2CppTypeEnum.I4:
        case Il2CppTypeEnum.U4:
        case Il2CppTypeEnum.CHAR:
        case Il2CppTypeEnum.R4:
        case Il2CppTypeEnum.R8:
            return typeof value == "number";
        case Il2CppTypeEnum.I8:
            return typeof value == "number" || value instanceof Int64;
        case Il2CppTypeEnum.U8:
            return typeof value == "number" || value instanceof UInt64;
        case Il2CppTypeEnum.I:
        case Il2CppTypeEnum.U:
        case Il2CppTypeEnum.PTR:
            return value instanceof NativePointer;
        case Il2CppTypeEnum.VALUETYPE:
            if (type.class.isEnum) return typeof value == "number";
            return value instanceof Il2CppValueType;
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.GENERICINST:
        case Il2CppTypeEnum.OBJECT:
            return value instanceof Il2CppObject;
        case Il2CppTypeEnum.STRING:
            return value instanceof Il2CppString;
        case Il2CppTypeEnum.SZARRAY:
            return value instanceof Il2CppArray;
        default:
            raise(`isCoherent: "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readFieldValue(pointer: NativePointer, type: Il2CppType): AllowedType {
    if (pointer.isNull()) {
        return undefined;
    }
    switch (type.typeEnum) {
        case Il2CppTypeEnum.VOID:
            return undefined;
        case Il2CppTypeEnum.BOOLEAN:
            return !!pointer.readS8();
        case Il2CppTypeEnum.I1:
            return pointer.readS8();
        case Il2CppTypeEnum.U1:
            return pointer.readU8();
        case Il2CppTypeEnum.I2:
            return pointer.readS16();
        case Il2CppTypeEnum.U2:
            return pointer.readU16();
        case Il2CppTypeEnum.I4:
            return pointer.readS32();
        case Il2CppTypeEnum.U4:
            return pointer.readU32();
        case Il2CppTypeEnum.CHAR:
            return pointer.readU16();
        case Il2CppTypeEnum.I8:
            return pointer.readS64();
        case Il2CppTypeEnum.U8:
            return pointer.readU64();
        case Il2CppTypeEnum.R4:
            return pointer.readFloat();
        case Il2CppTypeEnum.R8:
            return pointer.readDouble();
        case Il2CppTypeEnum.I:
        case Il2CppTypeEnum.U:
        case Il2CppTypeEnum.PTR:
            return pointer.readPointer();
        case Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? pointer.readS32() : new Il2CppValueType(pointer, type.class);
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.GENERICINST:
        case Il2CppTypeEnum.OBJECT:
            return new Il2CppObject(pointer.readPointer());
        case Il2CppTypeEnum.STRING:
            return new Il2CppString(pointer.readPointer());
        case Il2CppTypeEnum.SZARRAY:
            return new Il2CppArray(pointer.readPointer());
        default:
            raise(`readFieldValue: "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function writeFieldValue(pointer: NativePointer, value: AllowedType, type: Il2CppType) {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    switch (type.typeEnum) {
        case Il2CppTypeEnum.VOID:
            pointer.writePointer(NULL);
            break;
        case Il2CppTypeEnum.BOOLEAN: {
            pointer.writeU8(+(value as boolean));
            break;
        }
        case Il2CppTypeEnum.I1:
            pointer.writeS8(value as number);
            break;
        case Il2CppTypeEnum.U1:
            pointer.writeU8(value as number);
            break;
        case Il2CppTypeEnum.I2:
            pointer.writeS16(value as number);
            break;
        case Il2CppTypeEnum.U2:
            pointer.writeU16(value as number);
            break;
        case Il2CppTypeEnum.I4:
            pointer.writeS32(value as number);
            break;
        case Il2CppTypeEnum.U4:
            pointer.writeU32(value as number);
            break;
        case Il2CppTypeEnum.CHAR:
            pointer.writeU16(value as number);
            break;
        case Il2CppTypeEnum.I8: {
            const v = value instanceof Int64 ? value.toNumber() : (value as number);
            pointer.writeS64(v);
            break;
        }
        case Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : (value as number);
            pointer.writeS64(v);
            break;
        }
        case Il2CppTypeEnum.R4:
            pointer.writeFloat(value as number);
            break;
        case Il2CppTypeEnum.R8:
            pointer.writeDouble(value as number);
            break;
        case Il2CppTypeEnum.I:
        case Il2CppTypeEnum.U:
        case Il2CppTypeEnum.PTR:
            pointer.writePointer(value as NativePointer);
            break;
        case Il2CppTypeEnum.VALUETYPE:
            if (type.class.isEnum) pointer.writeS32(value as number);
            else pointer.writePointer((value as Il2CppValueType).handle);
            break;
        case Il2CppTypeEnum.STRING:
            pointer.writePointer((value as Il2CppString).handle);
            break;
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.OBJECT:
        case Il2CppTypeEnum.GENERICINST:
            pointer.writePointer((value as Il2CppObject).handle);
            break;
        case Il2CppTypeEnum.SZARRAY:
            pointer.writePointer((value as Il2CppArray<AllowedType>).handle);
            break;
        default:
            raise(`writeFieldValue: "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readRawValue(pointer: NativePointer, type: Il2CppType): AllowedType {
    if (pointer == undefined) {
        return;
    }
    switch (type.typeEnum) {
        case Il2CppTypeEnum.VOID:
            return;
        case Il2CppTypeEnum.BOOLEAN:
            return !!+pointer;
        case Il2CppTypeEnum.I1:
            return +pointer;
        case Il2CppTypeEnum.U1:
            return +pointer;
        case Il2CppTypeEnum.I2:
            return +pointer;
        case Il2CppTypeEnum.U2:
            return +pointer;
        case Il2CppTypeEnum.I4:
            return +pointer;
        case Il2CppTypeEnum.U4:
            return +pointer;
        case Il2CppTypeEnum.CHAR:
            return +pointer;
        case Il2CppTypeEnum.I8:
            return int64(pointer.toString());
        case Il2CppTypeEnum.U8:
            return int64(pointer.toString());
        case Il2CppTypeEnum.R4:
            return pointer.readFloat();
        case Il2CppTypeEnum.R8:
            return pointer.readDouble();
        case Il2CppTypeEnum.I:
        case Il2CppTypeEnum.U:
        case Il2CppTypeEnum.PTR:
            return pointer.isNull() ? NULL : pointer.readPointer();
        case Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? +pointer : new Il2CppValueType(pointer, type.class);
        case Il2CppTypeEnum.STRING:
            return pointer.isNull() ? undefined : new Il2CppString(pointer);
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.GENERICINST:
        case Il2CppTypeEnum.OBJECT:
            return new Il2CppObject(pointer);
        case Il2CppTypeEnum.SZARRAY:
            return new Il2CppArray(pointer);
        default:
            raise(`readRawValue: "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function allocRawValue(value: AllowedType, type: Il2CppType) {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    switch (type.typeEnum) {
        case Il2CppTypeEnum.VOID:
            return NULL;
        case Il2CppTypeEnum.BOOLEAN:
            return ptr(+(value as boolean));
        case Il2CppTypeEnum.I1:
            return ptr(value as number);
        case Il2CppTypeEnum.U1:
            return ptr(value as number);
        case Il2CppTypeEnum.I2:
            return ptr(value as number);
        case Il2CppTypeEnum.U2:
            return ptr(value as number);
        case Il2CppTypeEnum.I4:
            return ptr(value as number);
        case Il2CppTypeEnum.U4:
            return ptr(value as number);
        case Il2CppTypeEnum.CHAR:
            return ptr(value as number);
        case Il2CppTypeEnum.I8: {
            const v = value instanceof Int64 ? value.toNumber() : (value as number);
            return ptr(v);
        }
        case Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : (value as number);
            return ptr(v);
        }
        case Il2CppTypeEnum.R4:
            return Memory.alloc(4).writeFloat(value as number);
        case Il2CppTypeEnum.R8:
            return Memory.alloc(8).writeDouble(value as number);
        case Il2CppTypeEnum.PTR:
        case Il2CppTypeEnum.I:
        case Il2CppTypeEnum.U:
            return value as NativePointer;
        case Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? ptr(value as number) : (value as Il2CppValueType).handle;
        case Il2CppTypeEnum.STRING:
            return (value as Il2CppString).handle;
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.OBJECT:
        case Il2CppTypeEnum.GENERICINST:
            return (value as Il2CppObject).handle;
        case Il2CppTypeEnum.SZARRAY:
            return (value as Il2CppArray<AllowedType>).handle;
        default:
            raise(`allocRawValue: "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/**
 * Performs a dump of the assemblies.\
 * It's implemented is pure JS (which is a lot slower than the `CModule`
 * implementation).
 * Since `QuickJS` is not mature yet (and not ready for string concatenation),
 * remember to pick `V8` instead.
 * ```typescript
 * await Il2Cpp.initialize();
 * const Application = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image.classes["UnityEngine.Application"];
 * const version = Application.methods.get_version.invoke();
 * const identifier = Application.methods.get_identifier.invoke();
 * const persistentDataPath = Application.methods.get_persistentDataPath.invoke();
 * Il2Cpp.dump(`${persistentDataPath}/${identifier}_${version}.cs`);
 * ```
 * @param filename Where to save the dump. The caller has to
 * make sure the application has a write permission for that location.
 *
 */
export function dump(filename: string) {
    if (domain == undefined) {
        raise("Not yet initialized!");
    }

    const file = new File(filename, "w");

    for (const assembly of domain.assemblies) {
        inform(`Dumping ${assembly.name}...`);
        for (const klass of assembly.image.classes) file.write(klass.toString());
    }

    file.flush();
    file.close();
    ok(`Dump saved to ${filename}.`);
}
