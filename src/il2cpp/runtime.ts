import Il2CppValueType from "./value-type";
import Il2CppObject from "./object";
import Il2CppType from "./type";
import Il2CppArray from "./array";
import Il2CppString from "./string";
import {raise} from "../utils/console";
import {Il2CppTypeEnum} from "./type-enum";

/** @internal */
export type AllowedType =
    | undefined
    | boolean
    | number
    | Int64
    | UInt64
    | NativePointer
    | Il2CppValueType
    | Il2CppObject
    | Il2CppString
    | Il2CppArray<AllowedType>;

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
        case Il2CppTypeEnum.PTR:
            return value instanceof NativePointer;
        case Il2CppTypeEnum.VALUETYPE:
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
            raise(`isCoherent: case for "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
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
        case Il2CppTypeEnum.U:
        case Il2CppTypeEnum.PTR:
            return pointer.readPointer();
        case Il2CppTypeEnum.VALUETYPE:
            return new Il2CppValueType(pointer, type.class!);
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.GENERICINST:
        case Il2CppTypeEnum.OBJECT:
            return new Il2CppObject(pointer.readPointer());
        case Il2CppTypeEnum.STRING:
            return new Il2CppString(pointer.readPointer());
        case Il2CppTypeEnum.SZARRAY:
            return new Il2CppArray(pointer.readPointer());
        default:
            raise(`readFieldValue: case for "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
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
            const v = value instanceof Int64 ? value.toNumber() : value as number;
            pointer.writeS64(v);
            break;
        }
        case Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : value as number;
            pointer.writeS64(v);
            break;
        }
        case Il2CppTypeEnum.R4:
            pointer.writeFloat(value as number);
            break;
        case Il2CppTypeEnum.R8:
            pointer.writeDouble(value as number);
            break;
        case Il2CppTypeEnum.PTR:
            pointer.writePointer(value as NativePointer);
            break;
        case Il2CppTypeEnum.VALUETYPE:
            pointer.writePointer((value as Il2CppValueType).handle);
            break;
        case Il2CppTypeEnum.STRING:
            pointer.writePointer((value as Il2CppString).handle);
            break;
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.OBJECT:
        case Il2CppTypeEnum.GENERICINST:
            pointer.writePointer((value as Il2CppObject).handle);
            break;
        default:
            raise(`writeFieldValue: case for "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
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
        case Il2CppTypeEnum.PTR:
            return pointer.isNull() ? NULL : pointer.readPointer();
        case Il2CppTypeEnum.VALUETYPE:
            return new Il2CppValueType(pointer, type.class!);
        case Il2CppTypeEnum.STRING:
            return pointer.isNull() ? undefined : new Il2CppString(pointer);
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.GENERICINST:
        case Il2CppTypeEnum.OBJECT:
            return new Il2CppObject(pointer);
        case Il2CppTypeEnum.SZARRAY:
            return new Il2CppArray(pointer);
        default:
            raise(`readRawValue: case for "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
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
            const v = value instanceof Int64 ? value.toNumber() : value as number;
            return ptr(v);
        }
        case Il2CppTypeEnum.U8: {
            const v = value instanceof UInt64 ? value.toNumber() : value as number;
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
            return (value as Il2CppValueType).handle;
        case Il2CppTypeEnum.STRING:
            return (value as Il2CppString).handle;
        case Il2CppTypeEnum.CLASS:
        case Il2CppTypeEnum.OBJECT:
        case Il2CppTypeEnum.GENERICINST:
            return (value as Il2CppObject).handle;
        default:
            raise(`allocRawValue: case for "${type.name}" (${Il2CppTypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
    }
}

/** @internal */
export interface Valuable {
    valueHandle: NativePointer;
    value: AllowedType;
}

// export function choose(klass: Il2CppClass) {
//     const snapshot = Il2CppManagedMemorySnapshot.get();
//
//     const matches: Il2CppObject[] = [];
//
//     const count = snapshot.gcHandles.trackedObjectCount;
//     const start = snapshot.gcHandles.pointersToObjects;
//
//     for (let i = 0; i < count; i++) {
//         const object = new Il2CppObject(start.add(i * Process.pointerSize).readPointer());
//         if (object.class.handle.equals(klass.handle)) {
//             matches.push(object);
//         }
//     }
//
//     snapshot.free();
//
//     return matches;
// }

