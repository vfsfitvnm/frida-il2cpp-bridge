import { cache } from "decorator-cache-getter";

import { Accessor } from "../../utils/accessor";

import { Api } from "../api";
import { nonNullHandle } from "../decorators";
import { NativeStruct } from "../native-struct";
import { getOrNull } from "../utils";

import { _Il2CppField } from "./field";
import { _Il2CppGenericClass } from "./generic-class";
import { _Il2CppImage } from "./image";
import { _Il2CppMethod } from "./method";
import { _Il2CppType } from "./type";
import { _Il2CppTypeEnum } from "./type-enum";

/**
 * Represents a `Il2CppClass`.
 */
@nonNullHandle
export class _Il2CppClass extends NativeStruct {
    /**
     * The inverse of {@link _Il2CppClass.elementClass}.
     * @return The array class which has the caller as element class.
     */
    @cache
    get arrayClass(): _Il2CppClass {
        return new _Il2CppClass(Api._classGetArrayClass(this.handle, 1));
    }

    /**
     * @return The size as array element.
     */
    @cache
    get arrayElementSize(): number {
        return Api._classGetArrayElementSize(this.handle);
    }

    /**
     * @returns The name of the assembly it belongs to.
     */
    @cache
    get assemblyName(): string {
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
    @cache
    get declaringClass(): _Il2CppClass | null {
        return getOrNull(Api._classGetDeclaringType(this.handle), _Il2CppClass);
    }

    /**
     * Its element class if it's an array.
     */
    @cache
    get elementClass(): _Il2CppClass | null {
        return getOrNull(Api._classGetElementClass(this.handle), _Il2CppClass);
    }

    /**
     * @return The count of its fields.
     */
    @cache
    get fieldCount(): number {
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
    @cache
    get fields(): Accessor<_Il2CppField> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppField>();
        let handle: NativePointer;
        let field: _Il2CppField;
        while (!(handle = Api._classGetFields(this.handle, iterator)).isNull()) {
            field = new _Il2CppField(handle);
            accessor[field.name!] = field;
        }
        return accessor;
    }

    /**
     * @returns If it's a generic class, its generic class, `null` otherwise.
     */
    @cache
    get genericClass(): _Il2CppGenericClass | null {
        return getOrNull(Api._classGetGenericClass(this.handle), _Il2CppGenericClass);
    }

    /**
     * @return `true` if it has a static constructor, `false` otherwise.
     */
    @cache
    get hasStaticConstructor(): boolean {
        return Api._classHasStaticConstructor(this.handle);
    }

    /**
     * @return The image it belongs to.
     */
    @cache
    get image(): _Il2CppImage {
        return new _Il2CppImage(Api._classGetImage(this.handle));
    }

    /**
     * @return The size of its instance.
     */
    @cache
    get instanceSize(): number {
        return Api._classGetInstanceSize(this.handle);
    }

    /**
     * @return `true` if it's an `enum`, `false` otherwise.
     */
    @cache
    get isEnum(): boolean {
        return Api._classIsEnum(this.handle);
    }

    /**
     * @return `true` if it's an `interface`, `false` otherwise.
     */
    @cache
    get isInterface(): boolean {
        return Api._classIsInterface(this.handle);
    }

    /**
     * @return `true` If its static constructor has been already called,
     * so if its static data has been initialized, `false` otherwise.
     */
    get isStaticConstructorFinished(): boolean {
        return Api._classIsStaticConstructorFinished(this.handle);
    }

    /**
     * @return `true` if it's a value type (aka struct), `false` otherwise.
     */
    @cache
    get isStruct(): boolean {
        return Api._classIsStruct(this.handle) && !this.isEnum;
    }

    /**
     * @return The count of its implemented interfaces.
     */
    @cache
    get interfaceCount(): number {
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
    @cache
    get interfaces(): Accessor<_Il2CppClass> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppClass>();
        let handle: NativePointer;
        let klass: _Il2CppClass;
        while (!(handle = Api._classGetInterfaces(this.handle, iterator)).isNull()) {
            klass = new _Il2CppClass(handle);
            accessor[klass.type.name] = klass;
        }
        return accessor;
    }

    /**
     * @return The count of its methods.
     */
    @cache
    get methodCount(): number {
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
    @cache
    get methods(): Accessor<_Il2CppMethod> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppMethod>(true);
        let handle: NativePointer;
        let method: _Il2CppMethod;
        while (!(handle = Api._classGetMethods(this.handle, iterator)).isNull()) {
            method = new _Il2CppMethod(handle);
            accessor[method.name] = method;
        }
        return accessor;
    }

    /**
     * @return Its name.
     */
    @cache
    get name(): string {
        return Api._classGetName(this.handle)!;
    }

    /**
     * @return Its namespace.
     */
    @cache
    get namespace(): string {
        return Api._classGetNamespace(this.handle)!;
    }

    /**
     * @return Its parent if there is, `null.` otherwise.
     */
    @cache
    get parent(): _Il2CppClass | null {
        return getOrNull(Api._classGetParent(this.handle), _Il2CppClass);
    }

    /**
     * @return A pointer to its static fields.
     */
    @cache
    get staticFieldsData(): NativePointer {
        return Api._classGetStaticFieldData(this.handle);
    }

    /**
     * @return Its type.
     */
    @cache
    get type(): _Il2CppType {
        return new _Il2CppType(Api._classGetType(this.handle));
    }

    /**
     * It makes sure its static data has been initialized.\
     * See {@link isStaticConstructorFinished} for an example.
     */
    ensureInitialized(): void {
        Api._classInit(this.handle);
    }

    /**
     * It traces all its methods.\
     * See {@link Method.trace | trace} for more details.
     */
    trace(): void {
        for (const method of this.methods) method.trace();
    }

    /**
     * @return The class dump.
     */
    toString(): string {
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
                if (field.type.typeEnum == _Il2CppTypeEnum.STRING) text += '"';
                text += field.value;
                if (field.type.typeEnum == _Il2CppTypeEnum.STRING) text += '"';
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
