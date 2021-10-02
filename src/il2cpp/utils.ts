import { raise, warn } from "../utils/console";
import { NativeStruct } from "../utils/native-struct";
import { mapToArray } from "../utils/utils";

/** @internal */
export function read(pointer: NativePointer, type: Il2Cpp.Type): Il2Cpp.Field.Type {
    switch (type.typeEnum) {
        case Il2Cpp.Type.Enum.Boolean:
            return !!pointer.readS8();
        case Il2Cpp.Type.Enum.I1:
            return pointer.readS8();
        case Il2Cpp.Type.Enum.U1:
            return pointer.readU8();
        case Il2Cpp.Type.Enum.I2:
            return pointer.readS16();
        case Il2Cpp.Type.Enum.U2:
            return pointer.readU16();
        case Il2Cpp.Type.Enum.I4:
            return pointer.readS32();
        case Il2Cpp.Type.Enum.U4:
            return pointer.readU32();
        case Il2Cpp.Type.Enum.Char:
            return pointer.readU16();
        case Il2Cpp.Type.Enum.I8:
            return pointer.readS64();
        case Il2Cpp.Type.Enum.U8:
            return pointer.readU64();
        case Il2Cpp.Type.Enum.R4:
            return pointer.readFloat();
        case Il2Cpp.Type.Enum.R8:
            return pointer.readDouble();
        case Il2Cpp.Type.Enum.NativeInteger:
        case Il2Cpp.Type.Enum.UnsignedNativeInteger:
            return pointer.readPointer();
        case Il2Cpp.Type.Enum.Pointer:
            return new Il2Cpp.Pointer(pointer.readPointer(), type.class.baseType!);
        case Il2Cpp.Type.Enum.ValueType:
            return new Il2Cpp.ValueType(pointer, type);
        case Il2Cpp.Type.Enum.Object:
        case Il2Cpp.Type.Enum.Class:
            return new Il2Cpp.Object(pointer.readPointer());
        case Il2Cpp.Type.Enum.GenericInstance:
            return type.class.isValueType ? new Il2Cpp.ValueType(pointer, type) : new Il2Cpp.Object(pointer.readPointer());
        case Il2Cpp.Type.Enum.String:
            return new Il2Cpp.String(pointer.readPointer());
        case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
        case Il2Cpp.Type.Enum.Array:
            return new Il2Cpp.Array(pointer.readPointer());
    }

    raise(`read: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
}

/** @internal */
export function write(pointer: NativePointer, value: any, type: Il2Cpp.Type): NativePointer {
    if (type.isByReference) {
        return pointer.writePointer(value);
    }

    switch (type.typeEnum) {
        case Il2Cpp.Type.Enum.Boolean:
            return pointer.writeU8(+value);
        case Il2Cpp.Type.Enum.I1:
            return pointer.writeS8(value);
        case Il2Cpp.Type.Enum.U1:
            return pointer.writeU8(value);
        case Il2Cpp.Type.Enum.I2:
            return pointer.writeS16(value);
        case Il2Cpp.Type.Enum.U2:
            return pointer.writeU16(value);
        case Il2Cpp.Type.Enum.I4:
            return pointer.writeS32(value);
        case Il2Cpp.Type.Enum.U4:
            return pointer.writeU32(value);
        case Il2Cpp.Type.Enum.Char:
            return pointer.writeU16(value);
        case Il2Cpp.Type.Enum.I8:
            return pointer.writeS64(value);
        case Il2Cpp.Type.Enum.U8:
            return pointer.writeU64(value);
        case Il2Cpp.Type.Enum.R4:
            return pointer.writeFloat(value);
        case Il2Cpp.Type.Enum.R8:
            return pointer.writeDouble(value);
        case Il2Cpp.Type.Enum.NativeInteger:
        case Il2Cpp.Type.Enum.UnsignedNativeInteger:
        case Il2Cpp.Type.Enum.Pointer:
        case Il2Cpp.Type.Enum.ValueType:
        case Il2Cpp.Type.Enum.String:
        case Il2Cpp.Type.Enum.Object:
        case Il2Cpp.Type.Enum.Class:
        case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
        case Il2Cpp.Type.Enum.Array:
        case Il2Cpp.Type.Enum.GenericInstance:
            return pointer.writePointer(value);
    }

    raise(`write: "${type.name}" (${type.typeEnum}) has not been handled yet. Please file an issue!`);
}

/** @internal */
export function fromFridaValue(value: NativeFunctionReturnValue, type: Il2Cpp.Type): Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType {
    if (Array.isArray(value)) {
        return arrayToValueType(type, value);
    } else if (value instanceof NativePointer) {
        if (type.isByReference) {
            return new Il2Cpp.Reference(value, type);
        }

        switch (type.typeEnum) {
            case Il2Cpp.Type.Enum.Pointer:
                return new Il2Cpp.Pointer(value, type.class.baseType!);
            case Il2Cpp.Type.Enum.String:
                return new Il2Cpp.String(value);
            case Il2Cpp.Type.Enum.Class:
            case Il2Cpp.Type.Enum.GenericInstance:
            case Il2Cpp.Type.Enum.Object:
                return new Il2Cpp.Object(value);
            case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
            case Il2Cpp.Type.Enum.Array:
                return new Il2Cpp.Array(value);
            default:
                return value;
        }
    } else if (type.typeEnum == Il2Cpp.Type.Enum.Boolean) {
        return !!(value as number);
    } else {
        return value;
    }
}

/** @internal */
export function toFridaValue(value: Il2Cpp.Parameter.Type): NativeFunctionArgumentValue {
    if (typeof value == "boolean") {
        return +value;
    } else if (value instanceof Il2Cpp.ValueType) {
        return valueTypeToArray(value);
    } else {
        return value;
    }
}

function valueTypeToArray(value: Il2Cpp.ValueType): NativeFunctionArgumentValue[] {
    return mapToArray(value.fields, (field: Il2Cpp.Field) => {
        const fieldValue = field.value;
        return fieldValue instanceof Il2Cpp.ValueType
            ? valueTypeToArray(fieldValue)
            : fieldValue instanceof NativeStruct
            ? fieldValue.handle
            : typeof fieldValue == "boolean"
            ? +fieldValue
            : fieldValue;
    });
}

function arrayToValueType(type: Il2Cpp.Type, nativeValues: any[]): Il2Cpp.ValueType {
    function iter(type: Il2Cpp.Type, startOffset: number = 0): [Il2Cpp.Type.Enum, number][] {
        const arr: [Il2Cpp.Type.Enum, number][] = [];

        for (const field of Object.values(type.class.fields)) {
            if (!field.isStatic) {
                const offset = startOffset + field.offset - Il2Cpp.Runtime.objectHeaderSize;
                if (
                    field.type.typeEnum == Il2Cpp.Type.Enum.ValueType ||
                    (field.type.typeEnum == Il2Cpp.Type.Enum.GenericInstance && field.type.class.isValueType)
                ) {
                    arr.push(...iter(field.type, offset));
                } else {
                    arr.push([field.type.typeEnum, offset]);
                }
            }
        }

        return arr;
    }

    const valueType = Memory.alloc(type.class.valueSize);

    nativeValues = nativeValues.flat(Infinity);
    const typesAndOffsets = iter(type);

    for (let i = 0; i < nativeValues.length; i++) {
        const value = nativeValues[i];
        const [typeEnum, offset] = typesAndOffsets[i];
        const pointer = valueType.add(offset);

        switch (typeEnum) {
            case Il2Cpp.Type.Enum.Boolean:
                pointer.writeU8(value);
                break;
            case Il2Cpp.Type.Enum.I1:
                pointer.writeS8(value);
                break;
            case Il2Cpp.Type.Enum.U1:
                pointer.writeU8(value);
                break;
            case Il2Cpp.Type.Enum.I2:
                pointer.writeS16(value);
                break;
            case Il2Cpp.Type.Enum.U2:
                pointer.writeU16(value);
                break;
            case Il2Cpp.Type.Enum.I4:
                pointer.writeS32(value);
                break;
            case Il2Cpp.Type.Enum.U4:
                pointer.writeU32(value);
                break;
            case Il2Cpp.Type.Enum.Char:
                pointer.writeU16(value);
                break;
            case Il2Cpp.Type.Enum.I8:
                pointer.writeS64(value);
                break;
            case Il2Cpp.Type.Enum.U8:
                pointer.writeU64(value);
                break;
            case Il2Cpp.Type.Enum.R4:
                pointer.writeFloat(value);
                break;
            case Il2Cpp.Type.Enum.R8:
                pointer.writeDouble(value);
                break;
            case Il2Cpp.Type.Enum.NativeInteger:
            case Il2Cpp.Type.Enum.UnsignedNativeInteger:
            case Il2Cpp.Type.Enum.Pointer:
            case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
            case Il2Cpp.Type.Enum.Array:
            case Il2Cpp.Type.Enum.String:
            case Il2Cpp.Type.Enum.Object:
            case Il2Cpp.Type.Enum.Class:
            case Il2Cpp.Type.Enum.GenericInstance:
                pointer.writePointer(value);
                break;
            default:
                warn(`arrayToValueType: defaulting ${typeEnum} to pointer`);
                pointer.writePointer(value);
                break;
        }
    }

    return new Il2Cpp.ValueType(valueType, type);
}

/** @internal */
export function readGString(handle: NativePointer): string | null {
    try {
        return handle.readUtf8String();
    } finally {
        Il2Cpp.Api._gLibFree(handle);
    }
}
