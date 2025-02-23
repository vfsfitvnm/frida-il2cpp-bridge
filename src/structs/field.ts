namespace Il2Cpp {
    export class Field<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct {
        /** Gets the class in which this field is defined. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.exports.fieldGetClass(this));
        }

        /** Gets the flags of the current field. */
        @lazy
        get flags(): number {
            return Il2Cpp.exports.fieldGetFlags(this);
        }

        /** Determines whether this field value is known at compile time. */
        @lazy
        get isLiteral(): boolean {
            return (this.flags & Il2Cpp.Field.Attributes.Literal) != 0;
        }

        /** Determines whether this field is static. */
        @lazy
        get isStatic(): boolean {
            return (this.flags & Il2Cpp.Field.Attributes.Static) != 0;
        }

        /** Determines whether this field is thread static. */
        @lazy
        get isThreadStatic(): boolean {
            const offset = Il2Cpp.corlib.class("System.AppDomain").field("type_resolve_in_progress").offset;

            // prettier-ignore
            getter(Il2Cpp.Field.prototype, "isThreadStatic", function (this: Il2Cpp.Field) {
                return this.offset == offset;
            }, lazy);

            return this.isThreadStatic;
        }

        /** Gets the access modifier of this field. */
        @lazy
        get modifier(): string | undefined {
            switch (this.flags & Il2Cpp.Field.Attributes.FieldAccessMask) {
                case Il2Cpp.Field.Attributes.Private:
                    return "private";
                case Il2Cpp.Field.Attributes.FamilyAndAssembly:
                    return "private protected";
                case Il2Cpp.Field.Attributes.Assembly:
                    return "internal";
                case Il2Cpp.Field.Attributes.Family:
                    return "protected";
                case Il2Cpp.Field.Attributes.FamilyOrAssembly:
                    return "protected internal";
                case Il2Cpp.Field.Attributes.Public:
                    return "public";
            }
        }

        /** Gets the name of this field. */
        @lazy
        get name(): string {
            return Il2Cpp.exports.fieldGetName(this).readUtf8String()!;
        }

        /** Gets the offset of this field, calculated as the difference with its owner virtual address. */
        @lazy
        get offset(): number {
            return Il2Cpp.exports.fieldGetOffset(this);
        }

        /** Gets the type of this field. */
        @lazy
        get type(): Il2Cpp.Type {
            return new Il2Cpp.Type(Il2Cpp.exports.fieldGetType(this));
        }

        /** Gets the value of this field. */
        get value(): T {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }

            const handle = Memory.alloc(Process.pointerSize);
            Il2Cpp.exports.fieldGetStaticValue(this.handle, handle);

            return read(handle, this.type) as T;
        }

        /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
        set value(value: T) {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }

            if (this.isThreadStatic || this.isLiteral) {
                raise(`cannot write the value of field ${this.name} as it's thread static or literal`);
            }

            const handle =
                // pointer-like values should be passed as-is, but boxed
                // value types (primitives included) must be unboxed first
                value instanceof Il2Cpp.Object && this.type.class.isValueType
                    ? value.unbox()
                    : value instanceof NativeStruct
                    ? value.handle
                    : value instanceof NativePointer
                    ? value
                    : write(Memory.alloc(this.type.class.valueTypeSize), value, this.type);

            Il2Cpp.exports.fieldSetStaticValue(this.handle, handle);
        }

        /** */
        toString(): string {
            return `\
${this.isThreadStatic ? `[ThreadStatic] ` : ``}\
${this.isStatic ? `static ` : ``}\
${this.type.name} \
${this.name}\
${this.isLiteral ? ` = ${this.type.class.isEnum ? read((this.value as Il2Cpp.ValueType).handle, this.type.class.baseType!) : this.value}` : ``};\
${this.isThreadStatic || this.isLiteral ? `` : ` // 0x${this.offset.toString(16)}`}`;
        }

        /**
         * @internal
         * Binds the current field to a {@link Il2Cpp.Object} or a
         * {@link Il2Cpp.ValueType} (also known as *instances*), so that it is
         * possible to retrieve its value - see {@link Il2Cpp.Field.value} for
         * details. \
         * Binding a static field is forbidden.
         */
        bind(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.BoundField<T> {
            if (this.isStatic) {
                raise(`cannot bind static field ${this.class.type.name}::${this.name} to an instance`);
            }

            const valueHandle = instance.handle.add(this.offset - (instance instanceof Il2Cpp.ValueType ? Il2Cpp.Object.headerSize : 0));

            return new Proxy(this, {
                get(target: Il2Cpp.Field<T>, property: keyof Il2Cpp.Field): any {
                    if (property == "value") {
                        return read(valueHandle, target.type);
                    }
                    return Reflect.get(target, property);
                },

                set(target: Il2Cpp.Field<T>, property: keyof Il2Cpp.Field, value: any): boolean {
                    if (property == "value") {
                        write(valueHandle, value, target.type);
                        return true;
                    }

                    return Reflect.set(target, property, value);
                }
            });
        }
    }

    /**
     * A {@link Il2Cpp.Field} bound to a {@link Il2Cpp.Object} or a
     * {@link Il2Cpp.ValueType} (also known as *instances*).
     * ```ts
     * const object: Il2Cpp.Object = Il2Cpp.string("Hello, world!").object;
     * const m_length: Il2Cpp.BoundField<number> = object.field<number>("m_length");
     * const length = m_length.value; // 13
     * ```
     * Of course, binding a static field does not make sense and may cause
     * unwanted behaviors.
     * 
     * Binding can be done manually with:
     * ```ts
     * const SystemString = Il2Cpp.corlib.class("System.String");
     * const m_length: Il2Cpp.Field<number> = SystemString.field<number>("m_length");
     * 
     * const object: Il2Cpp.Object = Il2Cpp.string("Hello, world!").object;
     * // ＠ts-ignore
     * const m_length_bound: Il2Cpp.BoundField<number> = m_length.bind(object);
     * ```
     */
    export interface BoundField<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends Field<T> {
    }

    export namespace Field {
        export type Type = boolean | number | Int64 | UInt64 | NativePointer | Il2Cpp.Pointer | Il2Cpp.ValueType | Il2Cpp.Object | Il2Cpp.String | Il2Cpp.Array;

        export const enum Attributes {
            FieldAccessMask = 0x0007,
            PrivateScope = 0x0000,
            Private = 0x0001,
            FamilyAndAssembly = 0x0002,
            Assembly = 0x0003,
            Family = 0x0004,
            FamilyOrAssembly = 0x0005,
            Public = 0x0006,
            Static = 0x0010,
            InitOnly = 0x0020,
            Literal = 0x0040,
            NotSerialized = 0x0080,
            SpecialName = 0x0200,
            PinvokeImpl = 0x2000,
            ReservedMask = 0x9500,
            RTSpecialName = 0x0400,
            HasFieldMarshal = 0x1000,
            HasDefault = 0x8000,
            HasFieldRVA = 0x0100
        }
    }
}
