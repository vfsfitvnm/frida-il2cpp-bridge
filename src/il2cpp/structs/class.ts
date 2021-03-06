import { cache } from "decorator-cache-getter";
import { Api } from "../api";
import { getOrNull } from "../utils";
import { Accessor } from "../../utils/accessor";
import { Il2CppType } from "./type";
import { Il2CppField } from "./field";
import { Il2CppGenericClass } from "./generic-class";
import { Il2CppImage } from "./image";
import { Il2CppMethod } from "./method";
import { Il2CppTypeEnum } from "./type-enum";
import { NativeStruct } from "../native-struct";
import { nonNullHandle } from "../decorators";

/**
 * Represents a `Il2CppClass`.
 * ```typescript
 * const mscorlib = Il2Cpp.domain.assemblies.mscorlib.image;
 * //
 * const BooleanClass = mscorlib.classes["System.Boolean"];
 * const Int32Class = mscorlib.classes["System.Int32"];
 * const Int64Class = mscorlib.classes["System.Int64"];
 * const ObjectClass = mscorlib.classes["System.Object"];
 * const StringClass = mscorlib.classes["System.String"];
 * const DateTimeFormatInfoClass = mscorlib.classes["System.Globalization.DateTimeFormatInfo"];
 * const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"];
 * const MathClass = mscorlib.classes["System.Math"];
 * const IFormattableClass = mscorlib.classes["System.IFormattable"];
 * //
 * assert(BooleanClass.arrayClass.name == "Boolean[]");
 * //
 * assert(Int32Class.arrayElementSize == 4);
 * assert(Int64Class.arrayElementSize == 8);
 * assert(ObjectClass.arrayElementSize == Process.pointerSize);
 * //
 * assert(Int32Class.assemblyName == "mscorlib");
 * //
 * const ExecutionContext = mscorlib.classes["System.Threading.ExecutionContext"];
 * const Flags = mscorlib.classes["System.Threading.ExecutionContext.Flags"];
 * assert(ExecutionContext.handle.equals(Flags.declaringClass!.handle));
 * //
 * const dayNames = DateTimeFormatInfoClass.fields.dayNames;
 * assert(dayNames.type.name == "System.String[]");
 * assert(dayNames.type.class.elementClass!.type.name == "System.String");
 * //
 * assert(StringClass.hasStaticConstructor == (".cctor" in StringClass.methods));
 * assert(DateTimeFormatInfoClass.hasStaticConstructor == (".cctor" in DateTimeFormatInfoClass.methods));
 * //
 * assert(Int32Class.image.name == "mscorlib.dll");
 * //
 * assert(DayOfWeekClass.isEnum);
 * assert(!Int32Class.isEnum);
 * //
 * assert(IFormattableClass.isInterface);
 * //
 * if (!MathClass.isStaticConstructorFinished) {
 *     MathClass.ensureInitialized();
 *     assert(MathClass.isStaticConstructorFinished);
 * }
 * //
 * assert(Int32Class.isStruct);
 * assert(!StringClass.isStruct);
 * //
 * assert(BooleanClass.name == "Boolean");
 * //
 * assert(BooleanClass.namespace == "System");
 * //
 * assert(BooleanClass.parent!.type.name == "System.ValueType");
 * assert(ObjectClass.parent == null);
 * //
 * assert(BooleanClass.type.name == "System.Boolean");
 * ```
 */
@nonNullHandle
export class Il2CppClass extends NativeStruct {
    /**
     * The inverse of {@link Il2CppClass.elementClass}.
     * @return The array class which has the caller as element class.
     */
    @cache get arrayClass() {
        return new Il2CppClass(Api._classGetArrayClass(this.handle, 1));
    }

    /**
     * @return The size as array element.
     */
    @cache get arrayElementSize() {
        return Api._classGetArrayElementSize(this.handle);
    }

    /**
     * @returns The name of the assembly it belongs to.
     */
    @cache get assemblyName() {
        return Api._classGetAssemblyName(this.handle)!;
    }

    /**
     * ```csharp
     * namespace System.Threading
     * {
     *     class ExecutionContext
     *     {
     *         class Flags
     *         {
     *         }
     *     }
     * }
     * ```
     * @return Its outer class if its a nested class, `null` otherwise.
     */
    @cache get declaringClass() {
        return getOrNull(Api._classGetDeclaringType(this.handle), Il2CppClass);
    }

    /**
     * Its element class if it's an array.
     */
    @cache get elementClass() {
        return getOrNull(Api._classGetElementClass(this.handle), Il2CppClass);
    }

    /**
     * @return The count of its fields.
     */
    @cache get fieldCount() {
        return Api._classGetFieldCount(this.handle);
    }

    /**
     * We can iterate over the fields a `for..of` loop, or access
     * a specific field using its name.
     * ```typescript
     * const MathClass = mscorlib.classes["System.Math"];
     * for (const fields of MathClass.fields) {
     * }
     * const PI = MathClass.fields.PI;
     * ```
     * @return Its fields.
     */
    @cache get fields() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppField>();
        let handle: NativePointer;
        let field: Il2CppField;
        while (!(handle = Api._classGetFields(this.handle, iterator)).isNull()) {
            field = new Il2CppField(handle);
            accessor[field.name!] = field;
        }
        return accessor;
    }

    /**
     * @returns If it's a generic class, its generic class, `null` otherwise.
     */
    @cache get genericClass() {
        return getOrNull(Api._classGetGenericClass(this.handle), Il2CppGenericClass);
    }

    /**
     * @return `true` if it has a static constructor, `false` otherwise.
     */
    @cache get hasStaticConstructor() {
        return Api._classHasStaticConstructor(this.handle);
    }

    /**
     * @return The image it belongs to.
     */
    @cache get image() {
        return new Il2CppImage(Api._classGetImage(this.handle));
    }

    /**
     * @return The size of its instance.
     */
    @cache get instanceSize() {
        return Api._classGetInstanceSize(this.handle);
    }

    /**
     * @return `true` if it's an `enum`, `false` otherwise.
     */
    @cache get isEnum() {
        return Api._classIsEnum(this.handle);
    }

    /**
     * @return `true` if it's an `interface`, `false` otherwise.
     */
    @cache get isInterface() {
        return Api._classIsInterface(this.handle);
    }

    /**
     * @return `true` If its static constructor has been already called,
     * so if its static data has been initialized, `false` otherwise.
     */
    get isStaticConstructorFinished() {
        return Api._classIsStaticConstructorFinished(this.handle);
    }

    /**
     * @return `true` if it's a value type (aka struct), `false` otherwise.
     */
    @cache get isStruct() {
        return Api._classIsStruct(this.handle) && !this.isEnum;
    }

    /**
     * @return The count of its implemented interfaces.
     */
    @cache get interfaceCount() {
        return Api._classGetInterfaceCount(this.handle);
    }

    /**
     * We can iterate over the interfaces using a `for..of` loop,
     * or access a specific method using its name.
     * ```typescript
     * const StringClass = mscorlib.classes["System.String"];
     * for (const klass of StringClass.interfaces) {
     * }
     * const IComparable = StringClass.interfaces["System.IComparable"];
     * ```
     * @return Its interfaces.
     */
    @cache get interfaces() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppClass>();
        let handle: NativePointer;
        let klass: Il2CppClass;
        while (!(handle = Api._classGetInterfaces(this.handle, iterator)).isNull()) {
            klass = new Il2CppClass(handle);
            accessor[klass.type.name] = klass;
        }
        return accessor;
    }

    /**
     * @return The count of its methods.
     */
    @cache get methodCount() {
        return Api._classGetMethodCount(this.handle);
    }

    /**
     * We can iterate over the methods using a `for..of` loop,
     * or access a specific method using its name.
     * ```typescript
     * const MathClass = mscorlib.classes["System.Math"];
     * for (const method of MathClass.methods) {
     * }
     * const Log10 = MathClass.methods.Log10;
     * ```
     * @return Its methods.
     */
    @cache get methods() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppMethod>(true);
        let handle: NativePointer;
        let method: Il2CppMethod;
        while (!(handle = Api._classGetMethods(this.handle, iterator)).isNull()) {
            method = new Il2CppMethod(handle);
            accessor[method.name] = method;
        }
        return accessor;
    }

    /**
     * @return Its name.
     */
    @cache get name() {
        return Api._classGetName(this.handle)!;
    }

    /**
     * @return Its namespace.
     */
    @cache get namespace() {
        return Api._classGetNamespace(this.handle)!;
    }

    /**
     * @return Its parent if there is, `null.` otherwise.
     */
    @cache get parent() {
        return getOrNull(Api._classGetParent(this.handle), Il2CppClass);
    }

    /**
     * @return A pointer to its static fields.
     */
    @cache get staticFieldsData() {
        return Api._classGetStaticFieldData(this.handle);
    }

    /**
     * @return Its type.
     */
    @cache get type() {
        return new Il2CppType(Api._classGetType(this.handle));
    }

    /**
     * It makes sure its static data has been initialized.\
     * See {@link isStaticConstructorFinished} for an example.
     */
    ensureInitialized() {
        Api._classInit(this.handle);
    }

    /**
     * It traces all its methods.\
     * See {@link Method.trace | trace} for more details.
     */
    trace() {
        for (const method of this.methods) method.trace();
    }

    /**
     * @return The class dump.
     */
    toString() {
        const spacer = "\n    ";
        let text = "// " + this.image.name + "\n";
        text += this.isEnum ? "enum" : this.isStruct ? "struct" : this.isInterface ? "interface" : "class";
        text += " " + this.type.name;
        if (this.parent != null || this.interfaceCount > 0) text += " : ";
        if (this.parent != null) {
            text += this.parent.type.name;
            if (this.interfaceCount > 0) text += ", ";
        }
        if (this.interfaceCount > 0) text += Object.keys(this.interfaces).join(", ");
        text += "\n{";
        for (const field of this.fields) {
            text += spacer + (this.isEnum && field.name != "value__" ? "" : field.type.name + " ") + field.name;
            if (field.isLiteral) {
                text += " = ";
                if (field.type.typeEnum == Il2CppTypeEnum.STRING) text += '"';
                text += field.value;
                if (field.type.typeEnum == Il2CppTypeEnum.STRING) text += '"';
            }
            text += this.isEnum && field.name != "value__" ? "," : "; // 0x" + field.offset.toString(16);
        }
        if (this.fieldCount + this.methodCount > 0) text += "\n";
        for (const method of this.methods) {
            text += spacer;
            if (!method.isInstance) text += "static ";
            text += method.returnType.name + " " + method.name + "(";
            for (const parameter of method.parameters) {
                if (parameter.position > 0) text += ", ";
                text += parameter.type.name + " " + parameter.name;
            }
            text += ");";
            if (!method.actualPointer.isNull()) text += " // " + method.relativePointerAsString + ";";
        }
        text += "\n}\n\n";
        return text;
    }
}
