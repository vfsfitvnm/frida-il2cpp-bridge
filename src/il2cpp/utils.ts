import { raise, warn } from "../utils/console";

function isCoherent(value: Il2Cpp.AllowedType, type: Il2Cpp.Type): boolean {
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
            if (type.class.isEnum) {
                return typeof value == "number";
            }
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
    // if (pointer.isNull()) {
    //     return undefined;
    // }
    switch (type.typeEnum) {
        // case "void":
        //     return undefined;
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

export function fromFridaValue(value: NativeReturnValue, type: Il2Cpp.Type): Il2Cpp.AllowedType {
    // if (!isCoherent(value, type)) {
    //     raise(`A "${type.name}" was expected required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    // }

    if (Array.isArray(value)) {
        raise("...........");
    }

    if (value instanceof NativePointer) {
        if (type.isByReference) {
            return new Il2Cpp.Reference(value, type);
        }

        switch (type.typeEnum) {
            case "valuetype":
                return new Il2Cpp.ValueType(value, type.class);
            case "string":
                return new Il2Cpp.String(value);
            case "class":
            case "genericinst":
            case "object":
                return new Il2Cpp.Object(value);
            case "szarray":
                return new Il2Cpp.Array(value);
            default:
                warn(`readRaw: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
                return value;
        }
    } else if (type.typeEnum == "boolean") {
        return !!(value as number);
    } else {
        return value;
    }
}

export function toFridaValue(value: Il2Cpp.AllowedType, type: Il2Cpp.Type): NativeArgumentValue {
    // TODO: check type against value

    if (typeof value == "boolean") {
        return +value;
    } else {
        return value;
    }
}
