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
                switch (type?.typeEnum) {
                    case Il2Cpp.Type.Enum.U1:
                        return new Il2Cpp.Reference<T>(handle.writeU8(value), type);
                    case Il2Cpp.Type.Enum.I1:
                        return new Il2Cpp.Reference<T>(handle.writeS8(value), type);
                    case Il2Cpp.Type.Enum.Char:
                    case Il2Cpp.Type.Enum.U2:
                        return new Il2Cpp.Reference<T>(handle.writeU16(value), type);
                    case Il2Cpp.Type.Enum.I2:
                        return new Il2Cpp.Reference<T>(handle.writeS16(value), type);
                    case Il2Cpp.Type.Enum.U4:
                        return new Il2Cpp.Reference<T>(handle.writeU32(value), type);
                    case Il2Cpp.Type.Enum.I4:
                        return new Il2Cpp.Reference<T>(handle.writeS32(value), type);
                    case Il2Cpp.Type.Enum.U8:
                        return new Il2Cpp.Reference<T>(handle.writeU64(value), type);
                    case Il2Cpp.Type.Enum.I8:
                        return new Il2Cpp.Reference<T>(handle.writeS64(value), type);
                    case Il2Cpp.Type.Enum.R4:
                        return new Il2Cpp.Reference<T>(handle.writeFloat(value), type);
                    case Il2Cpp.Type.Enum.R8:
                        return new Il2Cpp.Reference<T>(handle.writeDouble(value), type);
                }
            case "object":
                if (value instanceof Il2Cpp.ValueType || value instanceof Il2Cpp.Pointer) {
                    return new Il2Cpp.Reference<T>(handle.writePointer(value), value.type);
                } else if (value instanceof Il2Cpp.Object) {
                    return new Il2Cpp.Reference<T>(handle.writePointer(value), value.class.type);
                } else if (value instanceof Il2Cpp.String || value instanceof Il2Cpp.Array) {
                    return new Il2Cpp.Reference<T>(handle.writePointer(value), value.object.class.type);
                } else if (value instanceof NativePointer) {
                    switch (type?.typeEnum) {
                        case Il2Cpp.Type.Enum.UnsignedNativeInteger:
                        case Il2Cpp.Type.Enum.NativeInteger:
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
