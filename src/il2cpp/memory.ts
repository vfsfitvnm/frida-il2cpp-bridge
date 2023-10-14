namespace Il2Cpp {
    /**
     * Allocates the given amount of bytes - it's equivalent to C's `malloc`. \
     * The allocated memory should be freed manually.
     */
    export function alloc(size: number | UInt64 = Process.pointerSize): NativePointer {
        return Il2Cpp.api.alloc(size);
    }

    /**
     * Frees a previously allocated memory using {@link Il2Cpp.alloc} - it's
     *  equivalent to C's `free`..
     *
     * ```ts
     * const handle = Il2Cpp.alloc(64);
     *
     * // ...
     *
     * Il2Cpp.free(handle);
     * ```
     */
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
            case Il2Cpp.Type.enum.string:
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return pointer.writePointer(value);
            case Il2Cpp.Type.enum.valueType:
                return Memory.copy(pointer, value, type.class.valueTypeSize), pointer;
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
            case Il2Cpp.Type.enum.genericInstance:
                return value instanceof Il2Cpp.ValueType ? (Memory.copy(pointer, value, type.class.valueTypeSize), pointer) : pointer.writePointer(value);
        }

        raise(`couldn't write value ${value} to ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }

    /** @internal */
    export function fromFridaValue(value: NativeCallbackArgumentValue, type: Il2Cpp.Type): Il2Cpp.Parameter.Type;

    /** @internal */
    export function fromFridaValue(value: NativeFunctionReturnValue, type: Il2Cpp.Type): Il2Cpp.Method.ReturnType;

    /** @internal */
    export function fromFridaValue(
        value: NativeCallbackArgumentValue | NativeFunctionReturnValue,
        type: Il2Cpp.Type
    ): Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType {
        if (globalThis.Array.isArray(value)) {
            const handle = Memory.alloc(type.class.valueTypeSize);
            const fields = type.class.fields.filter(_ => !_.isStatic);

            for (let i = 0; i < fields.length; i++) {
                const convertedValue = fromFridaValue(value[i], fields[i].type);
                write(handle.add(fields[i].offset).sub(Il2Cpp.Object.headerSize), convertedValue, fields[i].type);
            }

            return new Il2Cpp.ValueType(handle, type);
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
        } else if (type.typeEnum == Il2Cpp.Type.enum.valueType && type.class.isEnum) {
            return fromFridaValue([value], type);
        } else {
            return value;
        }
    }

    /** @internal */
    export function toFridaValue(value: Il2Cpp.Method.ReturnType): NativeFunctionReturnValue;

    /** @internal */
    export function toFridaValue(value: Il2Cpp.Parameter.Type): NativeFunctionArgumentValue;

    /** @internal */
    export function toFridaValue(value: Il2Cpp.Parameter.Type | Il2Cpp.Method.ReturnType): NativeFunctionArgumentValue | NativeFunctionReturnValue {
        if (typeof value == "boolean") {
            return +value;
        } else if (value instanceof Il2Cpp.ValueType) {
            if (value.type.class.isEnum) {
                return value.field<number | Int64 | UInt64>("value__").value;
            } else {
                const _ = value.type.class.fields.filter(_ => !_.isStatic).map(_ => toFridaValue(_.withHolder(value).value));
                return _.length == 0 ? [0] : _;
            }
        } else {
            return value;
        }
    }
}
