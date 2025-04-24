namespace Il2Cpp {
    /** Create a boxed primitive */
    export function boxed<T extends boolean | number | Int64 | UInt64 | NativePointer>(
        value: T,
        type?: T extends number
            ? "int8" | "uint8" | "int16" | "uint16" | "int32" | "uint32" | "int64" | "uint64" | "char"
            : T extends NativePointer
            ? "intptr" | "uintptr"
            : never
    ): Il2Cpp.Object {
        const mapping = {
            int8: "System.SByte",
            uint8: "System.Byte",
            int16: "System.Int16",
            uint16: "System.UInt16",
            int32: "System.Int32",
            uint32: "System.UInt32",
            int64: "System.Int64",
            uint64: "System.UInt64",
            char: "System.Char",
            intptr: "System.IntPtr",
            uintptr: "System.UIntPtr"
        };

        const className =
            typeof value == "boolean"
                ? "System.Boolean"
                : typeof value == "number"
                ? mapping[type ?? "int32"]
                : value instanceof Int64
                ? "System.Int64"
                : value instanceof UInt64
                ? "System.UInt64"
                : value instanceof NativePointer
                ? mapping[type ?? "intptr"]
                : raise(`Cannot create boxed primitive using value of type '${typeof value}'`);

        const object = Il2Cpp.corlib.class(className ?? raise(`Unknown primitive type name '${type}'`)).alloc();
        (object.tryField<T>("m_value") ?? object.tryField("_pointer") ?? raise(`Could not find primitive field in class '${className}'`)).value = value;

        return object;
    }
}
