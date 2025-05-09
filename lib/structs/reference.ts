namespace Il2Cpp {
    export class Reference<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct {
        constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
            super(handle);
        }

        /** Gets the element referenced by the current reference. */
        get value(): T {
            return read(this.handle, this.type) as T;
        }

        /** Sets the element referenced by the current reference. */
        set value(value: T) {
            write(this.handle, value, this.type);
        }

        /** */
        toString(): string {
            return this.isNull() ? "null" : `->${this.value}`;
        }
    }

    export function reference<T extends number | NativePointer>(value: T, type: Il2Cpp.Type): Il2Cpp.Reference<T>;

    export function reference<T extends Exclude<Il2Cpp.Field.Type, number | NativePointer>>(value: T): Il2Cpp.Reference<T>;

    /** Creates a reference to the specified value. */
    export function reference<T extends Il2Cpp.Field.Type>(value: T, type?: Il2Cpp.Type): Il2Cpp.Reference<T> {
        const handle = Memory.alloc(Process.pointerSize);

        switch (typeof value) {
            case "boolean":
                return new Il2Cpp.Reference(handle.writeS8(+value), Il2Cpp.corlib.class("System.Boolean").type);
            case "number":
                switch (type?.enumValue) {
                    case Il2Cpp.Type.Enum.UBYTE:
                        return new Il2Cpp.Reference<T>(handle.writeU8(value), type);
                    case Il2Cpp.Type.Enum.BYTE:
                        return new Il2Cpp.Reference<T>(handle.writeS8(value), type);
                    case Il2Cpp.Type.Enum.CHAR:
                    case Il2Cpp.Type.Enum.USHORT:
                        return new Il2Cpp.Reference<T>(handle.writeU16(value), type);
                    case Il2Cpp.Type.Enum.SHORT:
                        return new Il2Cpp.Reference<T>(handle.writeS16(value), type);
                    case Il2Cpp.Type.Enum.UINT:
                        return new Il2Cpp.Reference<T>(handle.writeU32(value), type);
                    case Il2Cpp.Type.Enum.INT:
                        return new Il2Cpp.Reference<T>(handle.writeS32(value), type);
                    case Il2Cpp.Type.Enum.ULONG:
                        return new Il2Cpp.Reference<T>(handle.writeU64(value), type);
                    case Il2Cpp.Type.Enum.LONG:
                        return new Il2Cpp.Reference<T>(handle.writeS64(value), type);
                    case Il2Cpp.Type.Enum.FLOAT:
                        return new Il2Cpp.Reference<T>(handle.writeFloat(value), type);
                    case Il2Cpp.Type.Enum.DOUBLE:
                        return new Il2Cpp.Reference<T>(handle.writeDouble(value), type);
                }
            case "object":
                if (value instanceof Il2Cpp.ValueType || value instanceof Il2Cpp.Pointer) {
                    return new Il2Cpp.Reference<T>(value.handle, value.type);
                } else if (value instanceof Il2Cpp.Object) {
                    return new Il2Cpp.Reference<T>(handle.writePointer(value), value.class.type);
                } else if (value instanceof Il2Cpp.String || value instanceof Il2Cpp.Array) {
                    return new Il2Cpp.Reference<T>(handle.writePointer(value), value.object.class.type);
                } else if (value instanceof NativePointer) {
                    switch (type?.enumValue) {
                        case Il2Cpp.Type.Enum.NUINT:
                        case Il2Cpp.Type.Enum.NINT:
                            return new Il2Cpp.Reference<T>(handle.writePointer(value), type);
                    }
                } else if (value instanceof Int64) {
                    return new Il2Cpp.Reference<T>(handle.writeS64(value), Il2Cpp.corlib.class("System.Int64").type);
                } else if (value instanceof UInt64) {
                    return new Il2Cpp.Reference<T>(handle.writeU64(value), Il2Cpp.corlib.class("System.UInt64").type);
                }
            default:
                raise(`couldn't create a reference to ${value} using an unhandled type ${type?.name}`);
        }
    }
}
