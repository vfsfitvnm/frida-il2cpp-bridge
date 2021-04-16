import { inform, ok, raise } from "../utils/console";

import { domain } from "./variables";
import { NativeStruct } from "./native-struct";
import { AllowedType } from "./types";

import { _Il2CppArray } from "./structs/array";
import { _Il2CppObject } from "./structs/object";
import { _Il2CppString } from "./structs/string";
import { _Il2CppValueType } from "./structs/value-type";
import { _Il2CppType } from "./structs/type";
import { _Il2CppTypeEnum } from "./structs/type-enum";

/** @internal */
export function getOrNull<T extends NativeStruct>(handle: NativePointer, Class: new (...args: any[]) => T) {
    return handle.isNull() ? null : new Class(handle);
}

/** @internal */
function isCoherent(value: AllowedType, type: _Il2CppType) {
    switch (type.typeEnum) {
        case _Il2CppTypeEnum.VOID:
            return value == undefined;
        case _Il2CppTypeEnum.BOOLEAN:
            return typeof value == "boolean";
        case _Il2CppTypeEnum.I1:
        case _Il2CppTypeEnum.U1:
        case _Il2CppTypeEnum.I2:
        case _Il2CppTypeEnum.U2:
        case _Il2CppTypeEnum.I4:
        case _Il2CppTypeEnum.U4:
        case _Il2CppTypeEnum.CHAR:
        case _Il2CppTypeEnum.R4:
        case _Il2CppTypeEnum.R8:
            return typeof value == "number";
        case _Il2CppTypeEnum.I8:
            return typeof value == "number" || value instanceof Int64;
        case _Il2CppTypeEnum.U8:
            return typeof value == "number" || value instanceof UInt64;
        case _Il2CppTypeEnum.I:
        case _Il2CppTypeEnum.U:
        case _Il2CppTypeEnum.PTR:
            return value instanceof NativePointer;
        case _Il2CppTypeEnum.VALUETYPE:
            if (type.class.isEnum) return typeof value == "number";
            return value instanceof _Il2CppValueType;
        case _Il2CppTypeEnum.CLASS:
        case _Il2CppTypeEnum.GENERICINST:
        case _Il2CppTypeEnum.OBJECT:
            return value instanceof _Il2CppObject;
        case _Il2CppTypeEnum.STRING:
            return value instanceof _Il2CppString;
        case _Il2CppTypeEnum.SZARRAY:
            return value instanceof _Il2CppArray;
        default:
            raise(`isCoherent: "${type.name}" (${_Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readFieldValue(pointer: NativePointer, type: _Il2CppType): AllowedType {
    if (pointer.isNull()) {
        return undefined;
    }
    switch (type.typeEnum) {
        case _Il2CppTypeEnum.VOID:
            return undefined;
        case _Il2CppTypeEnum.BOOLEAN:
            return !!pointer.readS8();
        case _Il2CppTypeEnum.I1:
            return pointer.readS8();
        case _Il2CppTypeEnum.U1:
            return pointer.readU8();
        case _Il2CppTypeEnum.I2:
            return pointer.readS16();
        case _Il2CppTypeEnum.U2:
            return pointer.readU16();
        case _Il2CppTypeEnum.I4:
            return pointer.readS32();
        case _Il2CppTypeEnum.U4:
            return pointer.readU32();
        case _Il2CppTypeEnum.CHAR:
            return pointer.readU16();
        case _Il2CppTypeEnum.I8:
            return pointer.readS64();
        case _Il2CppTypeEnum.U8:
            return pointer.readU64();
        case _Il2CppTypeEnum.R4:
            return pointer.readFloat();
        case _Il2CppTypeEnum.R8:
            return pointer.readDouble();
        case _Il2CppTypeEnum.I:
        case _Il2CppTypeEnum.U:
        case _Il2CppTypeEnum.PTR:
            return pointer.readPointer();
        case _Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? pointer.readS32() : new _Il2CppValueType(pointer, type.class);
        case _Il2CppTypeEnum.CLASS:
        case _Il2CppTypeEnum.GENERICINST:
        case _Il2CppTypeEnum.OBJECT:
            return new _Il2CppObject(pointer.readPointer());
        case _Il2CppTypeEnum.STRING:
            return new _Il2CppString(pointer.readPointer());
        case _Il2CppTypeEnum.SZARRAY:
            return new _Il2CppArray(pointer.readPointer());
        default:
            raise(`readFieldValue: "${type.name}" (${_Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function writeFieldValue(pointer: NativePointer, value: AllowedType, type: _Il2CppType) {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    switch (type.typeEnum) {
        case _Il2CppTypeEnum.VOID:
            pointer.writePointer(NULL);
            break;
        case _Il2CppTypeEnum.BOOLEAN: {
            pointer.writeU8(+(value as boolean));
            break;
        }
        case _Il2CppTypeEnum.I1:
            pointer.writeS8(value as number);
            break;
        case _Il2CppTypeEnum.U1:
            pointer.writeU8(value as number);
            break;
        case _Il2CppTypeEnum.I2:
            pointer.writeS16(value as number);
            break;
        case _Il2CppTypeEnum.U2:
            pointer.writeU16(value as number);
            break;
        case _Il2CppTypeEnum.I4:
            pointer.writeS32(value as number);
            break;
        case _Il2CppTypeEnum.U4:
            pointer.writeU32(value as number);
            break;
        case _Il2CppTypeEnum.CHAR:
            pointer.writeU16(value as number);
            break;
        case _Il2CppTypeEnum.I8: {
            const v = value instanceof Int64 ? value.toNumber() : (value as number);
            pointer.writeS64(v);
            break;
        }
        case _Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : (value as number);
            pointer.writeS64(v);
            break;
        }
        case _Il2CppTypeEnum.R4:
            pointer.writeFloat(value as number);
            break;
        case _Il2CppTypeEnum.R8:
            pointer.writeDouble(value as number);
            break;
        case _Il2CppTypeEnum.I:
        case _Il2CppTypeEnum.U:
        case _Il2CppTypeEnum.PTR:
            pointer.writePointer(value as NativePointer);
            break;
        case _Il2CppTypeEnum.VALUETYPE:
            if (type.class.isEnum) pointer.writeS32(value as number);
            else pointer.writePointer((value as _Il2CppValueType).handle);
            break;
        case _Il2CppTypeEnum.STRING:
            pointer.writePointer((value as _Il2CppString).handle);
            break;
        case _Il2CppTypeEnum.CLASS:
        case _Il2CppTypeEnum.OBJECT:
        case _Il2CppTypeEnum.GENERICINST:
            pointer.writePointer((value as _Il2CppObject).handle);
            break;
        case _Il2CppTypeEnum.SZARRAY:
            pointer.writePointer((value as _Il2CppArray<AllowedType>).handle);
            break;
        default:
            raise(`writeFieldValue: "${type.name}" (${_Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readRawValue(pointer: NativePointer, type: _Il2CppType): AllowedType {
    if (pointer == undefined) {
        return;
    }
    switch (type.typeEnum) {
        case _Il2CppTypeEnum.VOID:
            return;
        case _Il2CppTypeEnum.BOOLEAN:
            return !!+pointer;
        case _Il2CppTypeEnum.I1:
            return +pointer;
        case _Il2CppTypeEnum.U1:
            return +pointer;
        case _Il2CppTypeEnum.I2:
            return +pointer;
        case _Il2CppTypeEnum.U2:
            return +pointer;
        case _Il2CppTypeEnum.I4:
            return +pointer;
        case _Il2CppTypeEnum.U4:
            return +pointer;
        case _Il2CppTypeEnum.CHAR:
            return +pointer;
        case _Il2CppTypeEnum.I8:
            return int64(pointer.toString());
        case _Il2CppTypeEnum.U8:
            return int64(pointer.toString());
        case _Il2CppTypeEnum.R4:
            return pointer.readFloat();
        case _Il2CppTypeEnum.R8:
            return pointer.readDouble();
        case _Il2CppTypeEnum.I:
        case _Il2CppTypeEnum.U:
        case _Il2CppTypeEnum.PTR:
            return pointer.isNull() ? NULL : pointer.readPointer();
        case _Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? +pointer : new _Il2CppValueType(pointer, type.class);
        case _Il2CppTypeEnum.STRING:
            return pointer.isNull() ? undefined : new _Il2CppString(pointer);
        case _Il2CppTypeEnum.CLASS:
        case _Il2CppTypeEnum.GENERICINST:
        case _Il2CppTypeEnum.OBJECT:
            return new _Il2CppObject(pointer);
        case _Il2CppTypeEnum.SZARRAY:
            return new _Il2CppArray(pointer);
        default:
            raise(`readRawValue: "${type.name}" (${_Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function allocRawValue(value: AllowedType, type: _Il2CppType) {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    switch (type.typeEnum) {
        case _Il2CppTypeEnum.VOID:
            return NULL;
        case _Il2CppTypeEnum.BOOLEAN:
            return ptr(+(value as boolean));
        case _Il2CppTypeEnum.I1:
            return ptr(value as number);
        case _Il2CppTypeEnum.U1:
            return ptr(value as number);
        case _Il2CppTypeEnum.I2:
            return ptr(value as number);
        case _Il2CppTypeEnum.U2:
            return ptr(value as number);
        case _Il2CppTypeEnum.I4:
            return ptr(value as number);
        case _Il2CppTypeEnum.U4:
            return ptr(value as number);
        case _Il2CppTypeEnum.CHAR:
            return ptr(value as number);
        case _Il2CppTypeEnum.I8: {
            const v = value instanceof Int64 ? value.toNumber() : (value as number);
            return ptr(v);
        }
        case _Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : (value as number);
            return ptr(v);
        }
        case _Il2CppTypeEnum.R4:
            return Memory.alloc(4).writeFloat(value as number);
        case _Il2CppTypeEnum.R8:
            return Memory.alloc(8).writeDouble(value as number);
        case _Il2CppTypeEnum.PTR:
        case _Il2CppTypeEnum.I:
        case _Il2CppTypeEnum.U:
            return value as NativePointer;
        case _Il2CppTypeEnum.VALUETYPE:
            return type.class.isEnum ? ptr(value as number) : (value as _Il2CppValueType).handle;
        case _Il2CppTypeEnum.STRING:
            return (value as _Il2CppString).handle;
        case _Il2CppTypeEnum.CLASS:
        case _Il2CppTypeEnum.OBJECT:
        case _Il2CppTypeEnum.GENERICINST:
            return (value as _Il2CppObject).handle;
        case _Il2CppTypeEnum.SZARRAY:
            return (value as _Il2CppArray<AllowedType>).handle;
        default:
            raise(`allocRawValue: "${type.name}" (${_Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!`);
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
 * Il2Cpp.dump();
 * // Alternatively, providing a custom path
 * Il2Cpp.dump("/path/to/file.cs");
 * ```
 * @param filePath Where to save the dump. The caller has to
 * make sure the application has a write permission for that location.
 * If undefined, it will be automatically calculated. For instance, this will be
 * /storage/emulated/0/Android/data/com.example.application/files/com.example.application_1.2.3.cs.
 */
export function dump(filePath?: string) {
    if (domain == undefined) {
        raise("Not yet initialized!");
    }

    if (filePath == undefined) {
        const coreModuleName = "UnityEngine.CoreModule" in domain.assemblies ? "UnityEngine.CoreModule" : "UnityEngine";
        const applicationMethods = domain.assemblies[coreModuleName].image.classes["UnityEngine.Application"].methods;

        const persistentDataPath = applicationMethods.get_persistentDataPath.invoke<_Il2CppString>().content;

        const getIdentifierName = "get_identifier" in applicationMethods ? "get_identifier" : "get_bundleIdentifier";
        const identifier = applicationMethods[getIdentifierName].invoke<_Il2CppString>().content;
        const version = applicationMethods.get_version.invoke<_Il2CppString>().content;

        filePath = `${persistentDataPath}/${identifier}_${version}.cs`;
    }

    const file = new File(filePath, "w");

    for (const assembly of domain.assemblies) {
        inform(`Dumping ${assembly.name}...`);
        for (const klass of assembly.image.classes) {
            file.write(klass.toString());
        }
    }

    file.flush();
    file.close();
    ok(`Dump saved to ${filePath}.`);
}
