namespace Il2Cpp {
    @recycle
    export class Type extends NativeStruct {
        /** */
        @lazy
        static get Enum() {
            type NameToId = typeof map;
            type IdToName = { [K in keyof NameToId as NameToId[K]]: K };

            const _ = (_: string, block = (_: Il2Cpp.Class): { type: Il2Cpp.Type } => _) => block(Il2Cpp.corlib.class(_)).type.enumValue;

            const map = {
                VOID: _("System.Void"),
                BOOLEAN: _("System.Boolean"),
                CHAR: _("System.Char"),
                BYTE: _("System.SByte"),
                UBYTE: _("System.Byte"),
                SHORT: _("System.Int16"),
                USHORT: _("System.UInt16"),
                INT: _("System.Int32"),
                UINT: _("System.UInt32"),
                LONG: _("System.Int64"),
                ULONG: _("System.UInt64"),
                NINT: _("System.IntPtr"),
                NUINT: _("System.UIntPtr"),
                FLOAT: _("System.Single"),
                DOUBLE: _("System.Double"),
                POINTER: _("System.IntPtr", _ => _.field("m_value")),
                VALUE_TYPE: _("System.Decimal"),
                OBJECT: _("System.Object"),
                STRING: _("System.String"),
                CLASS: _("System.Array"),
                ARRAY: _("System.Void", _ => _.arrayClass),
                NARRAY: _("System.Void", _ => new Il2Cpp.Class(Il2Cpp.exports.classGetArrayClass(_, 2))),
                GENERIC_INSTANCE: _("System.Int32", _ => _.interfaces.find(_ => _.name.endsWith("`1"))!)
            };

            const reversed: IdToName = globalThis.Object.fromEntries(globalThis.Object.entries(map).map(_ => _.reverse()));

            return globalThis.Object.assign(map, reversed);
        }

        /** Gets the class of this type. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.exports.typeGetClass(this));
        }

        /** */
        @lazy
        get fridaAlias(): NativeCallbackArgumentType {
            function getValueTypeFields(type: Il2Cpp.Type): NativeCallbackArgumentType {
                const instanceFields = type.class.fields.filter(_ => !_.isStatic);
                return instanceFields.length == 0 ? ["char"] : instanceFields.map(_ => _.type.fridaAlias);
            }

            if (this.isByReference) {
                return "pointer";
            }

            switch (this.enumValue) {
                case Il2Cpp.Type.Enum.VOID:
                    return "void";
                case Il2Cpp.Type.Enum.BOOLEAN:
                    return "bool";
                case Il2Cpp.Type.Enum.CHAR:
                    return "uchar";
                case Il2Cpp.Type.Enum.BYTE:
                    return "int8";
                case Il2Cpp.Type.Enum.UBYTE:
                    return "uint8";
                case Il2Cpp.Type.Enum.SHORT:
                    return "int16";
                case Il2Cpp.Type.Enum.USHORT:
                    return "uint16";
                case Il2Cpp.Type.Enum.INT:
                    return "int32";
                case Il2Cpp.Type.Enum.UINT:
                    return "uint32";
                case Il2Cpp.Type.Enum.LONG:
                    return "int64";
                case Il2Cpp.Type.Enum.ULONG:
                    return "uint64";
                case Il2Cpp.Type.Enum.FLOAT:
                    return "float";
                case Il2Cpp.Type.Enum.DOUBLE:
                    return "double";
                case Il2Cpp.Type.Enum.NINT:
                case Il2Cpp.Type.Enum.NUINT:
                case Il2Cpp.Type.Enum.POINTER:
                case Il2Cpp.Type.Enum.STRING:
                case Il2Cpp.Type.Enum.ARRAY:
                case Il2Cpp.Type.Enum.NARRAY:
                    return "pointer";
                case Il2Cpp.Type.Enum.VALUE_TYPE:
                    return this.class.isEnum ? this.class.baseType!.fridaAlias : getValueTypeFields(this);
                case Il2Cpp.Type.Enum.CLASS:
                case Il2Cpp.Type.Enum.OBJECT:
                case Il2Cpp.Type.Enum.GENERIC_INSTANCE:
                    return this.class.isStruct ? getValueTypeFields(this) : this.class.isEnum ? this.class.baseType!.fridaAlias : "pointer";
                default:
                    return "pointer";
            }
        }

        /** Determines whether this type is passed by reference. */
        @lazy
        get isByReference(): boolean {
            return this.name.endsWith("&");
        }

        /** Determines whether this type is primitive. */
        @lazy
        get isPrimitive(): boolean {
            switch (this.enumValue) {
                case Il2Cpp.Type.Enum.BOOLEAN:
                case Il2Cpp.Type.Enum.CHAR:
                case Il2Cpp.Type.Enum.BYTE:
                case Il2Cpp.Type.Enum.UBYTE:
                case Il2Cpp.Type.Enum.SHORT:
                case Il2Cpp.Type.Enum.USHORT:
                case Il2Cpp.Type.Enum.INT:
                case Il2Cpp.Type.Enum.UINT:
                case Il2Cpp.Type.Enum.LONG:
                case Il2Cpp.Type.Enum.ULONG:
                case Il2Cpp.Type.Enum.FLOAT:
                case Il2Cpp.Type.Enum.DOUBLE:
                case Il2Cpp.Type.Enum.NINT:
                case Il2Cpp.Type.Enum.NUINT:
                    return true;
                default:
                    return false;
            }
        }

        /** Gets the name of this type. */
        @lazy
        get name(): string {
            const handle = Il2Cpp.exports.typeGetName(this);

            try {
                return handle.readUtf8String()!;
            } finally {
                Il2Cpp.free(handle);
            }
        }

        /** Gets the encompassing object of the current type. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.exports.typeGetObject(this));
        }

        /** Gets the {@link Il2Cpp.Type.Enum} value of the current type. */
        @lazy
        get enumValue(): number {
            return Il2Cpp.exports.typeGetTypeEnum(this);
        }

        is(other: Il2Cpp.Type): boolean {
            try {
                return !!Il2Cpp.exports.typeEquals(this, other);
            } catch (_) {
                return this.object.method<boolean>("Equals").invoke(other.object);
            }
        }

        /** */
        toString(): string {
            return this.name;
        }
    }
}
