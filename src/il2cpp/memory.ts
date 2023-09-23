namespace Il2Cpp {
    /** Allocates the given amount of bytes. */
    export function alloc(size: number | UInt64 = Process.pointerSize): NativePointer {
        return Il2Cpp.api.alloc(size);
    }

    /** Frees memory. */
    export function free(pointer: NativePointerValue): void {
        return Il2Cpp.api.free(pointer);
    }

    /** @internal */
    export function read(pointer: NativePointer, type: Il2Cpp.Type): Il2Cpp.Field.Type {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return !!pointer.readS8();
            case Il2Cpp.Type.enum.byte:
                return pointer.readS8();
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.readU8();
            case Il2Cpp.Type.enum.short:
                return pointer.readS16();
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.readU16();
            case Il2Cpp.Type.enum.int:
                return pointer.readS32();
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.readU32();
            case Il2Cpp.Type.enum.char:
                return pointer.readU16();
            case Il2Cpp.Type.enum.long:
                return pointer.readS64();
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.readU64();
            case Il2Cpp.Type.enum.float:
                return pointer.readFloat();
            case Il2Cpp.Type.enum.double:
                return pointer.readDouble();
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
                return pointer.readPointer();
            case Il2Cpp.Type.enum.pointer:
                return new Il2Cpp.Pointer(pointer.readPointer(), type.class.baseType!);
            case Il2Cpp.Type.enum.valueType:
                return new Il2Cpp.ValueType(pointer, type);
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
                return new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.genericInstance:
                return type.class.isValueType ? new Il2Cpp.ValueType(pointer, type) : new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.string:
                return new Il2Cpp.String(pointer.readPointer());
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return new Il2Cpp.Array(pointer.readPointer());
        }

        raise(`couldn't read the value from ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }

    /** @internal */
    export function write(pointer: NativePointer, value: any, type: Il2Cpp.Type): NativePointer {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return pointer.writeS8(+value);
            case Il2Cpp.Type.enum.byte:
                return pointer.writeS8(value);
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.writeU8(value);
            case Il2Cpp.Type.enum.short:
                return pointer.writeS16(value);
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.int:
                return pointer.writeS32(value);
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.writeU32(value);
            case Il2Cpp.Type.enum.char:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.long:
                return pointer.writeS64(value);
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.writeU64(value);
            case Il2Cpp.Type.enum.float:
                return pointer.writeFloat(value);
            case Il2Cpp.Type.enum.double:
                return pointer.writeDouble(value);
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
            case Il2Cpp.Type.enum.pointer:
            case Il2Cpp.Type.enum.valueType:
            case Il2Cpp.Type.enum.string:
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
            case Il2Cpp.Type.enum.genericInstance:
                if (value instanceof Il2Cpp.ValueType) {
                    Memory.copy(pointer, value, type.class.valueTypeSize);
                    return pointer;
                }

                return pointer.writePointer(value);
        }

        raise(`couldn't write value ${value} to ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }

    /** @internal */
    export function fromFridaValue(value: NativeFunctionReturnValue, type: Il2Cpp.Type): Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType {
        if (globalThis.Array.isArray(value)) {
            return arrayToValueType(type, value);
        } else if (value instanceof NativePointer) {
            if (type.isByReference) {
                return new Il2Cpp.Reference(value, type);
            }

            switch (type.typeEnum) {
                case Il2Cpp.Type.enum.pointer:
                    return new Il2Cpp.Pointer(value, type.class.baseType!);
                case Il2Cpp.Type.enum.string:
                    return new Il2Cpp.String(value);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.genericInstance:
                case Il2Cpp.Type.enum.object:
                    return new Il2Cpp.Object(value);
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return new Il2Cpp.Array(value);
                default:
                    return value;
            }
        } else if (type.typeEnum == Il2Cpp.Type.enum.boolean) {
            return !!(value as number);
        } else if (type.class.isEnum) {
            return arrayToValueType(type, [value]);
        } else {
            return value;
        }
    }

    /** @internal */
    export function toFridaValue(value: Il2Cpp.Method.ReturnType): NativeFunctionReturnValue;
    export function toFridaValue(value: Il2Cpp.Parameter.Type): NativeFunctionArgumentValue;
    export function toFridaValue(value: Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType): NativeFunctionArgumentValue | NativeFunctionReturnValue {
        if (typeof value == "boolean") {
            return +value;
        } else if (value instanceof Il2Cpp.ValueType) {
            return value.type.class.isEnum ? value.field<number>("value__").value : valueTypeToArray(value);
        } else {
            return value;
        }
    }

    /** @internal */
    function valueTypeToArray(value: Il2Cpp.ValueType): NativeFunctionArgumentValue[] {
        const instanceFields = value.type.class.fields.filter(_ => !_.isStatic);

        return instanceFields.length == 0
            ? [value.handle.readU8()]
            : instanceFields
                  .map(_ => _.withHolder(value).value)
                  .map(value =>
                      value instanceof Il2Cpp.ValueType
                          ? valueTypeToArray(value)
                          : value instanceof NativeStruct
                          ? value.handle
                          : typeof value == "boolean"
                          ? +value
                          : value
                  );
    }

    /** @internal */
    function arrayToValueType(type: Il2Cpp.Type, nativeValues: any[]): Il2Cpp.ValueType {
        function iter(type: Il2Cpp.Type, startOffset: number = 0): [number, number][] {
            const arr: [number, number][] = [];

            for (const field of type.class.fields) {
                if (!field.isStatic) {
                    const offset = startOffset + field.offset - Il2Cpp.Object.headerSize;
                    if (
                        field.type.typeEnum == Il2Cpp.Type.enum.valueType ||
                        (field.type.typeEnum == Il2Cpp.Type.enum.genericInstance && field.type.class.isValueType)
                    ) {
                        arr.push(...iter(field.type, offset));
                    } else {
                        arr.push([field.type.typeEnum, offset]);
                    }
                }
            }

            if (arr.length == 0) {
                arr.push([Il2Cpp.Type.enum.unsignedByte, 0]);
            }

            return arr;
        }

        const valueType = Memory.alloc(type.class.valueTypeSize);

        nativeValues = nativeValues.flat(Infinity);
        const typesAndOffsets = iter(type);

        for (let i = 0; i < nativeValues.length; i++) {
            const value = nativeValues[i];
            const [typeEnum, offset] = typesAndOffsets[i];
            const pointer = valueType.add(offset);

            switch (typeEnum) {
                case Il2Cpp.Type.enum.boolean:
                    pointer.writeS8(value);
                    break;
                case Il2Cpp.Type.enum.byte:
                    pointer.writeS8(value);
                    break;
                case Il2Cpp.Type.enum.unsignedByte:
                    pointer.writeU8(value);
                    break;
                case Il2Cpp.Type.enum.short:
                    pointer.writeS16(value);
                    break;
                case Il2Cpp.Type.enum.unsignedShort:
                    pointer.writeU16(value);
                    break;
                case Il2Cpp.Type.enum.int:
                    pointer.writeS32(value);
                    break;
                case Il2Cpp.Type.enum.unsignedInt:
                    pointer.writeU32(value);
                    break;
                case Il2Cpp.Type.enum.char:
                    pointer.writeU16(value);
                    break;
                case Il2Cpp.Type.enum.long:
                    pointer.writeS64(value);
                    break;
                case Il2Cpp.Type.enum.unsignedLong:
                    pointer.writeU64(value);
                    break;
                case Il2Cpp.Type.enum.float:
                    pointer.writeFloat(value);
                    break;
                case Il2Cpp.Type.enum.double:
                    pointer.writeDouble(value);
                    break;
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                case Il2Cpp.Type.enum.pointer:
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                case Il2Cpp.Type.enum.string:
                case Il2Cpp.Type.enum.object:
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.genericInstance:
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
}
