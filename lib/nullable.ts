namespace Il2Cpp {
    /**
     * Wraps the given primitive or value type in a `System.Nullable<T>`, also
     * known as a nullable value type (`T?`), to represent primitive or value
     * types that _might_ be null
     * ([ref](https://learn.microsoft.com/dotnet/csharp/language-reference/builtin-types/nullable-value-types)). \
     * Reference types **shall not** be turned into nullable, as they are
     * already covered by the C# `null` keywork and `new Il2Cpp.Object(NULL)` in Frida.
     *
     * ```ts
     * const nullableBoolean = Il2Cpp.nullable(false);
     * const nullableInt32 = Il2Cpp.nullable(13);
     * const nullableValueType = Il2Cpp.nullable(myValueType);
     *
     * const nullableNumber = Il2Cpp.nullable(13, Il2Cpp.corlib.class("System.UInt16"));
     * const nullableUnsignedPointer = Il2Cpp.nullable(ptr(0xdeadbeef), Il2Cpp.corlib.class("System.UIntPtr"));
     *
     * const nullPrimitiveOrValueType = Il2Cpp.nullable(null, Il2Cpp.corlib.class("..."));
     * ```
     * Internally, `System.Nullable<T>` prepends to the value type values
     * layout a boolean to indicate whether it's not null:
     * ```c#
     * struct System.Nullable<System.Int32> : System.ValueType
     * {
     *       System.Boolean hasValue; // 0x10
     *       System.Int32 value; // 0x14
     *       ...
     * }
     */
    export function nullable(value: null | number | NativePointer, klass: Il2Cpp.Class): Il2Cpp.ValueType;

    export function nullable(value: boolean | number | Int64 | UInt64 | NativePointer | Il2Cpp.ValueType): Il2Cpp.ValueType;

    export function nullable(valueOrNull: null | boolean | number | Int64 | UInt64 | NativePointer | Il2Cpp.ValueType, klass?: Il2Cpp.Class): Il2Cpp.ValueType {
        const actualClass =
            typeof valueOrNull == "boolean"
                ? Il2Cpp.corlib.class("System.Boolean")
                : typeof valueOrNull == "number"
                  ? (klass ?? Il2Cpp.corlib.class("System.Int32"))
                  : valueOrNull instanceof Int64
                    ? Il2Cpp.corlib.class("System.Int64")
                    : valueOrNull instanceof UInt64
                      ? Il2Cpp.corlib.class("System.UInt64")
                      : valueOrNull instanceof NativePointer
                        ? (klass ?? Il2Cpp.corlib.class("System.IntPtr"))
                        : valueOrNull instanceof Il2Cpp.ValueType
                          ? valueOrNull.type.class
                          : (klass ?? raise(`A class must be specified when constructing a nullable for value '${valueOrNull}'`));

        if (actualClass.isValueType == false) {
            raise(`Cannot create nullable value type out of a reference type '${actualClass.type.name}'`);
        }

        const inflatedClass = Il2Cpp.corlib.class("System.Nullable`1").inflate(actualClass);
        const struct = new Il2Cpp.ValueType(Memory.alloc(inflatedClass.valueTypeSize), inflatedClass.type);

        (struct.tryField<boolean>("hasValue") ?? struct.field<boolean>("has_value")).value = valueOrNull != null;
        if (valueOrNull != null) {
            struct.field("value").value = valueOrNull;
        }

        return struct;
    }
}
