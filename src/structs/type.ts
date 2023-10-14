namespace Il2Cpp {
    @recycle
    export class Type extends NativeStruct {
        /** */
        @lazy
        static get enum() {
            const _ = (_: string, block = (_: Il2Cpp.Class): { type: Il2Cpp.Type } => _) => block(Il2Cpp.corlib.class(_)).type.typeEnum;

            return {
                void: _("System.Void"),
                boolean: _("System.Boolean"),
                char: _("System.Char"),
                byte: _("System.SByte"),
                unsignedByte: _("System.Byte"),
                short: _("System.Int16"),
                unsignedShort: _("System.UInt16"),
                int: _("System.Int32"),
                unsignedInt: _("System.UInt32"),
                long: _("System.Int64"),
                unsignedLong: _("System.UInt64"),
                nativePointer: _("System.IntPtr"),
                unsignedNativePointer: _("System.UIntPtr"),
                float: _("System.Single"),
                double: _("System.Double"),
                pointer: _("System.IntPtr", _ => _.field("m_value")),
                valueType: _("System.Decimal"),
                object: _("System.Object"),
                string: _("System.String"),
                class: _("System.Array"),
                array: _("System.Void", _ => _.arrayClass),
                multidimensionalArray: _("System.Void", _ => new Il2Cpp.Class(Il2Cpp.api.classGetArrayClass(_, 2))),
                genericInstance: _("System.Int32", _ => _.interfaces.find(_ => _.name.endsWith("`1"))!)
            };
        }

        /** Gets the class of this type. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.api.typeGetClass(this));
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

            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.void:
                    return "void";
                case Il2Cpp.Type.enum.boolean:
                    return "bool";
                case Il2Cpp.Type.enum.char:
                    return "uchar";
                case Il2Cpp.Type.enum.byte:
                    return "int8";
                case Il2Cpp.Type.enum.unsignedByte:
                    return "uint8";
                case Il2Cpp.Type.enum.short:
                    return "int16";
                case Il2Cpp.Type.enum.unsignedShort:
                    return "uint16";
                case Il2Cpp.Type.enum.int:
                    return "int32";
                case Il2Cpp.Type.enum.unsignedInt:
                    return "uint32";
                case Il2Cpp.Type.enum.long:
                    return "int64";
                case Il2Cpp.Type.enum.unsignedLong:
                    return "uint64";
                case Il2Cpp.Type.enum.float:
                    return "float";
                case Il2Cpp.Type.enum.double:
                    return "double";
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                case Il2Cpp.Type.enum.pointer:
                case Il2Cpp.Type.enum.string:
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return "pointer";
                case Il2Cpp.Type.enum.valueType:
                    return this.class.isEnum ? this.class.baseType!.fridaAlias : getValueTypeFields(this);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.object:
                case Il2Cpp.Type.enum.genericInstance:
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
            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.boolean:
                case Il2Cpp.Type.enum.char:
                case Il2Cpp.Type.enum.byte:
                case Il2Cpp.Type.enum.unsignedByte:
                case Il2Cpp.Type.enum.short:
                case Il2Cpp.Type.enum.unsignedShort:
                case Il2Cpp.Type.enum.int:
                case Il2Cpp.Type.enum.unsignedInt:
                case Il2Cpp.Type.enum.long:
                case Il2Cpp.Type.enum.unsignedLong:
                case Il2Cpp.Type.enum.float:
                case Il2Cpp.Type.enum.double:
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                    return true;
                default:
                    return false;
            }
        }

        /** Gets the name of this type. */
        @lazy
        get name(): string {
            const handle = Il2Cpp.api.typeGetName(this);

            try {
                return handle.readUtf8String()!;
            } finally {
                Il2Cpp.free(handle);
            }
        }

        /** Gets the encompassing object of the current type. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.api.typeGetObject(this));
        }

        /** Gets the type enum of the current type. */
        @lazy
        get typeEnum(): number {
            return Il2Cpp.api.typeGetTypeEnum(this);
        }

        /** */
        toString(): string {
            return this.name;
        }
    }
}
