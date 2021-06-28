import { raise } from "../utils/console";

function isCoherent(value: Il2Cpp.AllowedType, type: Il2Cpp.Type): boolean {
    if (type.isByReference) {
        return value instanceof NativePointer;
    }

    switch (type.typeEnum) {
        case "void":
            return value == undefined;
        case "boolean":
            return typeof value == "boolean";
        case "i1":
        case "u1":
        case "i2":
        case "u2":
        case "i4":
        case "u4":
        case "char":
        case "r4":
        case "r8":
            return typeof value == "number";
        case "i8":
            return typeof value == "number" || value instanceof Int64;
        case "u8":
            return typeof value == "number" || value instanceof UInt64;
        case "i":
        case "u":
        case "ptr":
            return value instanceof NativePointer;
        case "valuetype":
            if (type.class.isEnum) return typeof value == "number";
            return value instanceof Il2Cpp.ValueType;
        case "class":
        case "genericinst":
        case "object":
            return value instanceof Il2Cpp.Object;
        case "string":
            return value instanceof Il2Cpp.String;
        case "szarray":
            return value instanceof Il2Cpp.Array;
        default:
            raise(`isCoherent: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readFieldValue(pointer: NativePointer, type: Il2Cpp.Type): Il2Cpp.AllowedType {
    if (pointer.isNull()) {
        return undefined;
    }
    switch (type.typeEnum) {
        case "void":
            return undefined;
        case "boolean":
            return !!pointer.readS8();
        case "i1":
            return pointer.readS8();
        case "u1":
            return pointer.readU8();
        case "i2":
            return pointer.readS16();
        case "u2":
            return pointer.readU16();
        case "i4":
            return pointer.readS32();
        case "u4":
            return pointer.readU32();
        case "char":
            return pointer.readU16();
        case "i8":
            return pointer.readS64();
        case "u8":
            return pointer.readU64();
        case "r4":
            return pointer.readFloat();
        case "r8":
            return pointer.readDouble();
        case "i":
        case "u":
        case "ptr":
            return pointer.readPointer();
        case "valuetype":
            return type.class.isEnum ? pointer.readS32() : new Il2Cpp.ValueType(pointer, type.class);
        case "class":
        case "genericinst":
        case "object":
            return new Il2Cpp.Object(pointer.readPointer());
        case "string":
            return new Il2Cpp.String(pointer.readPointer());
        case "szarray":
            return new Il2Cpp.Array(pointer.readPointer());
        default:
            raise(`readFieldValue: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function writeFieldValue(pointer: NativePointer, value: Il2Cpp.AllowedType, type: Il2Cpp.Type): void {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    switch (type.typeEnum) {
        case "void":
            pointer.writePointer(NULL);
            break;
        case "boolean":
            pointer.writeU8(+(value as boolean));
            break;
        case "i1":
            pointer.writeS8(value as number);
            break;
        case "u1":
            pointer.writeU8(value as number);
            break;
        case "i2":
            pointer.writeS16(value as number);
            break;
        case "u2":
            pointer.writeU16(value as number);
            break;
        case "i4":
            pointer.writeS32(value as number);
            break;
        case "u4":
            pointer.writeU32(value as number);
            break;
        case "char":
            pointer.writeU16(value as number);
            break;
        case "i8":
            pointer.writeS64(value instanceof Int64 ? value.toNumber() : (value as number));
            break;
        case "u8":
            pointer.writeS64(value instanceof UInt64 ? value.toNumber() : (value as number));
            break;
        case "r4":
            pointer.writeFloat(value as number);
            break;
        case "r8":
            pointer.writeDouble(value as number);
            break;
        case "i":
        case "u":
        case "ptr":
            pointer.writePointer(value as NativePointer);
            break;
        case "valuetype":
            if (type.class.isEnum) pointer.writeS32(value as number);
            else pointer.writePointer((value as Il2Cpp.ValueType).handle);
            break;
        case "string":
            pointer.writePointer((value as Il2Cpp.String).handle);
            break;
        case "class":
        case "object":
        case "genericinst":
            pointer.writePointer((value as Il2Cpp.Object).handle);
            break;
        case "szarray":
            pointer.writePointer((value as Il2Cpp.Array<Il2Cpp.AllowedType>).handle);
            break;
        default:
            raise(`writeFieldValue: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function readRawValue(pointer: NativePointer, type: Il2Cpp.Type): Il2Cpp.AllowedType {
    if (pointer == undefined) {
        return;
    }

    // if (type.isByReference) {
    //     return readRawValue(pointer.readPointer(), type.class.type);
    // }

    switch (type.typeEnum) {
        case "void":
            return;
        case "boolean":
            return !!+pointer;
        case "i1":
            return +pointer;
        case "u1":
            return +pointer;
        case "i2":
            return +pointer;
        case "u2":
            return +pointer;
        case "i4":
            return +pointer;
        case "u4":
            return +pointer;
        case "char":
            return +pointer;
        case "i8":
            return int64(pointer.toString());
        case "u8":
            return uint64(pointer.toString());
        case "r4":
            return pointer.readFloat();
        case "r8":
            return pointer.readDouble();
        case "i":
        case "u":
        case "ptr":
            return pointer.isNull() ? NULL : pointer.readPointer();
        case "valuetype":
            return type.class.isEnum ? +pointer : new Il2Cpp.ValueType(pointer, type.class);
        case "string":
            return pointer.isNull() ? undefined : new Il2Cpp.String(pointer);
        case "class":
        case "genericinst":
        case "object":
            return new Il2Cpp.Object(pointer);
        case "szarray":
            return new Il2Cpp.Array(pointer);
        default:
            raise(`readRawValue: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

/** @internal */
export function allocRawValue(value: Il2Cpp.AllowedType, type: Il2Cpp.Type): NativePointer {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }

    // if (type.isByReference) {
    //     return Memory.alloc(Process.pointerSize).writePointer(allocRawValue(value, type.class.type));
    // }

    switch (type.typeEnum) {
        case "void":
            return NULL;
        case "boolean":
            return ptr(+(value as boolean));
        case "i1":
            return ptr(value as number);
        case "u1":
            return ptr(value as number);
        case "i2":
            return ptr(value as number);
        case "u2":
            return ptr(value as number);
        case "i4":
            return ptr(value as number);
        case "u4":
            return ptr(value as number);
        case "char":
            return ptr(value as number);
        case "i8":
            return ptr(value instanceof Int64 ? value.toNumber() : (value as number));
        case "u8":
            return ptr(value instanceof UInt64 ? value.toNumber() : (value as number));
        case "r4":
            return Memory.alloc(4).writeFloat(value as number);
        case "r8":
            return Memory.alloc(8).writeDouble(value as number);
        case "ptr":
        case "i":
        case "u":
            return value as NativePointer;
        case "valuetype":
            return type.class.isEnum ? ptr(value as number) : (value as Il2Cpp.ValueType).handle;
        case "string":
            return (value as Il2Cpp.String).handle;
        case "class":
        case "object":
        case "genericinst":
            return (value as Il2Cpp.Object).handle;
        case "szarray":
            return (value as Il2Cpp.Array<Il2Cpp.AllowedType>).handle;
        default:
            raise(`allocRawValue: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}
