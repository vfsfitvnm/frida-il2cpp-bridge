import { raise } from "../utils/console";

function checkCoherence(value: Il2Cpp.Field.Type, type: Il2Cpp.Type) {
    if (!isCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }
}

function isCoherent(value: Il2Cpp.Field.Type, type: Il2Cpp.Type): boolean {
    if (type.isByReference) {
        return value instanceof Il2Cpp.Reference;
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
            return value instanceof NativePointer;
        case "ptr":
            return value instanceof Il2Cpp.Pointer;
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

function isNativeReturnValueCoherent(value: NativeReturnValue, type: Il2Cpp.Type): boolean {
    if (type.isByReference) {
        return value instanceof NativePointer;
    } else if (Array.isArray(value)) {
        raise("This should not happen.");
    }

    switch (type.typeEnum) {
        case "void":
            return typeof value == "undefined";
        case "boolean":
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
            return value instanceof Int64;
        case "u8":
            return value instanceof UInt64;
        case "valuetype":
            if (type.class.isEnum) {
                return typeof value == "number";
            }
            return value instanceof NativePointer;
        case "i":
        case "u":
        case "ptr":
        case "class":
        case "genericinst":
        case "object":
        case "string":
        case "szarray":
            return value instanceof NativePointer;
        default:
            raise(`isCoherent: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

function checkNativeReturnValueCoherence(value: NativeReturnValue, type: Il2Cpp.Type): value is NativePointer {
    if (!isNativeReturnValueCoherent(value, type)) {
        raise(`A "${type.name}" is required, but a "${Object.getPrototypeOf(value).constructor.name}" was supplied.`);
    }
    return true;
}

/** @internal */
export function readFieldValue(pointer: NativePointer, type: Il2Cpp.Type): Il2Cpp.Field.Type {
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
            return pointer.readPointer();
        case "ptr":
            return new Il2Cpp.Pointer(pointer.readPointer(), type.dataType!);
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
export function writeFieldValue(pointer: NativePointer, value: Il2Cpp.Field.Type, type: Il2Cpp.Type): void {
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
            pointer.writePointer(value as NativePointer);
            break;
        case "ptr":
            pointer.writePointer(value as Il2Cpp.Pointer);
            break;
        case "valuetype":
            if (type.class.isEnum) pointer.writeS32(value as number);
            else pointer.writePointer(value as Il2Cpp.ValueType);
            break;
        case "string":
            pointer.writePointer(value as Il2Cpp.String);
            break;
        case "class":
        case "object":
        case "genericinst":
            pointer.writePointer(value as Il2Cpp.Object);
            break;
        case "szarray":
            pointer.writePointer(value as Il2Cpp.Array);
            break;
        default:
            raise(`writeFieldValue: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
    }
}

export function fromFridaValue(value: NativeReturnValue, type: Il2Cpp.Type): Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType {
    // checkNativeReturnValueCoherence(value, type);

    if (Array.isArray(value)) {
        return value as any;
    } else if (value instanceof NativePointer) {
        if (type.isByReference) {
            return new Il2Cpp.Reference(value, type);
        }

        switch (type.typeEnum) {
            case "ptr":
                return new Il2Cpp.Pointer(value, type.dataType!);
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
                return value;
        }
    } else if (type.typeEnum == "boolean") {
        return !!(value as number);
    } else {
        return value as any;
    }
}

export function toFridaValue(value: Il2Cpp.Parameter.Type, type: Il2Cpp.Type): NativeArgumentValue {
    // TODO: check type against value
    const j = type.typeEnum;

    if (typeof value == "boolean") {
        return +value;
    } else {
        return value;
    }
}
